"""Multi-stage AIOps Security Agent Orchestrator."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiops_auditor.agents.investigator import AutonomousSecurityInvestigator
from aiops_auditor.agents.prompts import DEFENSIVE_SYSTEM_PROMPT, build_finding_audit_prompt
from aiops_auditor.intel.cve_kb import CVEKnowledgeBase
from aiops_auditor.llm.base import BaseLLMClient, create_llm_client
from aiops_auditor.llm.heuristic_fallback import HeuristicLLMClient
from aiops_auditor.models import (
    AuditPolicy,
    AuditReport,
    Finding,
    LLMVerdict,
    ModelProfile,
    Severity,
)
from aiops_auditor.scanners import (
    extract_manifest_packages,
    load_external_sarif,
    scan_dependency_manifest,
    scan_iac_file,
    scan_native_lowlevel,
    scan_secrets,
    scan_source_code,
)

MAX_FILE_BYTES = 512 * 1024  # 512 KB safety cap per text file
TEXT_EXTENSIONS = {
    ".php",
    ".phtml",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".py",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".hh",
    ".s",
    ".asm",
    ".rs",
    ".mk",
    ".cmake",
    ".gyp",
    ".makefile",
    ".tf",
    ".tfvars",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".txt",
    ".sh",
    ".ps1",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
}
SPECIAL_FILENAMES = {
    "dockerfile",
    "makefile",
    "jenkinsfile",
    "cmakelists.txt",
    "binding.gyp",
    "meson.build",
}

FUNC_DEF_RE = re.compile(
    r"(?:def|function|public\s+\S+|private\s+\S+|protected\s+\S+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)


class AIOpsAuditOrchestrator:
    """Coordinates deterministic scanning, context slicing, LLM taint verification, and policy gating."""

    def __init__(
        self,
        profile: ModelProfile,
        policy: AuditPolicy,
        llm_client: BaseLLMClient | None = None,
        strict_llm: bool = False,
        cve_kb: CVEKnowledgeBase | None = None,
    ) -> None:
        self.profile = profile
        self.policy = policy
        self.strict_llm = strict_llm
        self._llm_client = llm_client or create_llm_client(profile)
        self.cve_kb = cve_kb or CVEKnowledgeBase()

    def _is_scannable_file(self, path: Path) -> bool:
        name_lower = path.name.lower()
        if name_lower in SPECIAL_FILENAMES or name_lower.startswith("dockerfile."):
            return True
        return path.suffix.lower() in TEXT_EXTENSIONS

    def _iter_target_files(self, target_root: Path) -> list[Path]:
        if target_root.is_file():
            return [target_root] if self._is_scannable_file(target_root) else []

        excluded = set(self.policy.excluded_dirs)
        collected: list[Path] = []
        for root, dirs, files in os.walk(target_root):
            # Prune excluded subdirectories (relative to target_root)
            dirs[:] = [d for d in sorted(dirs) if d not in excluded]
            for filename in sorted(files):
                fpath = Path(root) / filename
                if not self._is_scannable_file(fpath):
                    continue
                try:
                    if fpath.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                collected.append(fpath)
        return collected

    def _build_symbol_callers(
        self, file_contents: dict[str, str]
    ) -> dict[str, list[str]]:
        """Lightweight cross-file symbol index so the LLM sees caller entrypoints."""
        defined_symbols: set[str] = set()
        for content in file_contents.values():
            for match in FUNC_DEF_RE.finditer(content):
                sym = match.group(1)
                if len(sym) >= 4:
                    defined_symbols.add(sym)

        caller_map: dict[str, list[str]] = {}
        for rel_path, content in file_contents.items():
            lines = content.splitlines()
            for idx, line in enumerate(lines, start=1):
                for sym in defined_symbols:
                    if f"{sym}(" in line and not FUNC_DEF_RE.search(line):
                        caller_map.setdefault(sym, []).append(f"{rel_path}:{idx}: {line.strip()[:100]}")
        return caller_map

    def _slice_context(self, content: str, line_no: int) -> tuple[str, str, list[str]]:
        lines = content.splitlines()
        # Extract imports / headers from top of file
        headers = [
            f"{i + 1}: {ln}"
            for i, ln in enumerate(lines[:25])
            if re.match(r"^\s*(import |from |require|const |use |include|resource |provider )", ln)
        ]

        start = max(0, line_no - 1 - self.policy.context_lines_before)
        end = min(len(lines), line_no + self.policy.context_lines_after)
        slice_str = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))

        # Identify enclosing symbol name for cross-file caller lookup
        enclosing_symbols: list[str] = []
        for idx in range(min(line_no - 1, len(lines) - 1), max(-1, line_no - 40), -1):
            m = FUNC_DEF_RE.search(lines[idx])
            if m:
                enclosing_symbols.append(m.group(1))
                break

        return slice_str, "\n".join(headers[:12]), enclosing_symbols

    def _resolve_active_llm(self) -> tuple[BaseLLMClient, str | None]:
        """Verify live LLM availability; gracefully degrade to heuristic unless strict_llm=True."""
        if self._llm_client.health_check():
            return self._llm_client, None

        if self.strict_llm:
            raise RuntimeError(
                f"LLM backend '{self._llm_client.backend_name}' for profile '{self.profile.name}' "
                f"is unreachable and --strict-llm is enabled."
            )

        reason = (
            f"Backend '{self._llm_client.backend_name}' ({self.profile.model}) unreachable; "
            "degraded gracefully to deterministic heuristic auditor."
        )
        return HeuristicLLMClient(self.profile), reason

    def _triage_with_agent(
        self,
        finding: Finding,
        client: BaseLLMClient,
        file_contents: dict[str, str],
        caller_map: dict[str, list[str]],
    ) -> LLMVerdict:
        content = file_contents.get(finding.file_path, finding.snippet)
        context_slice, headers, symbols = self._slice_context(content, finding.line)

        caller_hints: list[str] = []
        for sym in symbols:
            finding.related_symbols.append(sym)
            caller_hints.extend(caller_map.get(sym, [])[:3])

        user_prompt = build_finding_audit_prompt(
            finding=finding,
            context_slice=context_slice,
            header_imports=headers,
            caller_hints=caller_hints,
        )

        try:
            raw = client.analyze_json(DEFENSIVE_SYSTEM_PROMPT, user_prompt)
            status = str(raw.get("status", "needs_review")).lower()
            if status not in ("confirmed", "needs_review", "false_positive"):
                status = "needs_review"

            adjusted_sev = Severity.from_str(
                str(raw.get("adjusted_severity", finding.severity.value))
            )
            confidence = float(raw.get("confidence", 0.7))
            confidence = max(0.0, min(1.0, confidence))

            return LLMVerdict(
                status=status,
                adjusted_severity=adjusted_sev,
                confidence=confidence,
                taint_analysis=str(raw.get("taint_analysis", "")).strip(),
                remediation_summary=str(
                    raw.get("remediation_summary", finding.remediation)
                ).strip(),
                suggested_patch=str(raw.get("suggested_patch", "")).strip(),
                model_used=f"{client.backend_name}:{self.profile.model}",
            )
        except Exception as exc:  # noqa: BLE001
            return LLMVerdict(
                status="needs_review",
                adjusted_severity=finding.severity,
                confidence=0.5,
                taint_analysis=f"LLM triage error ({type(exc).__name__}); retaining static finding.",
                remediation_summary=finding.remediation,
                suggested_patch="",
                model_used=f"{client.backend_name}:{self.profile.model}",
            )

    def run_audit(
        self,
        target_path: Path,
        external_sarif_files: list[Path] | None = None,
        explicit_files: list[Path] | None = None,
    ) -> AuditReport:
        """Execute the full multi-stage security audit pipeline."""
        resolved_target = target_path.resolve()
        if explicit_files is not None:
            files = [
                f.resolve()
                for f in explicit_files
                if f.exists() and f.is_file() and self._is_scannable_file(f)
            ]
        else:
            files = self._iter_target_files(resolved_target)

        file_contents: dict[str, str] = {}
        file_paths_by_rel: dict[str, Path] = {}
        discovered_packages: list[tuple[str, str, str]] = []
        raw_findings: list[Finding] = []

        # Stage 0: Read target files & extract project dependency inventory
        for fpath in files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = (
                fpath.name
                if resolved_target.is_file()
                else fpath.relative_to(resolved_target).as_posix()
            )
            file_contents[rel_path] = content
            file_paths_by_rel[rel_path] = fpath
            discovered_packages.extend(extract_manifest_packages(fpath, content))

        # Auto-refresh local CVE Knowledge Base (CISA KEV + OSV.dev + NVD) when requested
        sync_stats_dict: dict[str, Any] | None = None
        if self.policy.auto_sync_cve:
            sync_stats = self.cve_kb.sync_all(
                eco_packages=discovered_packages,
                nvd_keywords=["php", "node.js", "openssl", "spring", "next.js"],
                include_nvd=False,
            )
            sync_stats_dict = sync_stats.to_dict()

        # Stage 1: Deterministic multi-layer discovery (enriched with live CVE KB)
        for rel_path, content in file_contents.items():
            fpath = file_paths_by_rel[rel_path]
            raw_findings.extend(scan_source_code(fpath, rel_path, content))
            raw_findings.extend(scan_native_lowlevel(fpath, rel_path, content))
            raw_findings.extend(
                scan_dependency_manifest(
                    fpath,
                    rel_path,
                    content,
                    enable_osv_lookup=self.policy.enable_osv_lookup,
                    cve_kb=self.cve_kb,
                )
            )
            raw_findings.extend(scan_iac_file(fpath, rel_path, content))
            raw_findings.extend(scan_secrets(fpath, rel_path, content))

        if external_sarif_files:
            for sarif_file in external_sarif_files:
                raw_findings.extend(load_external_sarif(sarif_file))

        # Deduplicate & prioritize highest severity first
        seen: set[tuple[str, str, int]] = set()
        findings: list[Finding] = []
        for f in sorted(raw_findings, key=lambda x: (-x.severity.rank, x.file_path, x.line)):
            key = (f.rule_id, f.file_path, f.line)
            if key not in seen:
                seen.add(key)
                findings.append(f)

        # Stage 2 & 3: Context slicing + AI Triage & Remediation Agent
        caller_map = self._build_symbol_callers(file_contents)
        active_client, fallback_reason = self._resolve_active_llm()

        triaged_count = 0
        for finding in findings[: self.policy.max_llm_findings]:
            finding.verdict = self._triage_with_agent(
                finding=finding,
                client=active_client,
                file_contents=file_contents,
                caller_map=caller_map,
            )
            triaged_count += 1

        # Stage 3b: Autonomous Multi-Step Investigation Agent (ReAct Tool-Use Loop)
        investigation_meta: dict[str, Any] = {
            "enabled": self.policy.enable_autonomous_agent,
            "steps_executed": 0,
            "discovered_count": 0,
            "tool_trace": [],
            "summary": "",
        }
        if self.policy.enable_autonomous_agent:
            investigator = AutonomousSecurityInvestigator(
                llm_client=active_client,
                file_contents=file_contents,
                cve_kb=self.cve_kb,
                existing_findings=findings,
                max_steps=self.policy.max_agent_steps,
            )
            inv_result = investigator.run()
            investigation_meta = {
                "enabled": True,
                "steps_executed": inv_result.steps_executed,
                "discovered_count": len(inv_result.discovered_findings),
                "tool_trace": inv_result.tool_trace,
                "summary": inv_result.summary,
            }
            for disc in inv_result.discovered_findings:
                d_key = (disc.rule_id, disc.file_path, disc.line)
                if d_key not in seen:
                    seen.add(d_key)
                    findings.append(disc)

        # Stage 4: Policy Gate & Summary Counts
        counts: dict[str, int] = {sev.value: 0 for sev in Severity}
        counts["SUPPRESSED_FP"] = 0
        gate_passed = True

        for finding in findings:
            if (
                self.policy.allowed_false_positive_suppression
                and finding.is_suppressed_false_positive
            ):
                counts["SUPPRESSED_FP"] += 1
                continue

            eff = finding.effective_severity
            counts[eff.value] += 1
            if eff.rank >= self.policy.fail_on_severity.rank:
                gate_passed = False

        metadata: dict[str, Any] = {
            "vram_gb_required": self.profile.vram_gb_required,
            "model_tier": self.profile.tier,
            "model_license": self.profile.license,
            "triaged_by_agent": triaged_count,
            "osv_lookup_enabled": self.policy.enable_osv_lookup,
            "cve_kb_entries": len(self.cve_kb.entries),
            "cve_kb_last_synced": self.cve_kb.last_synced_at or "baseline",
            "autonomous_agent": investigation_meta,
        }
        if sync_stats_dict:
            metadata["cve_kb_sync"] = sync_stats_dict
        if fallback_reason:
            metadata["fallback_notice"] = fallback_reason

        return AuditReport(
            target_path=str(resolved_target),
            generated_at=datetime.now(timezone.utc).isoformat(),
            profile_name=self.profile.name,
            model_name=self.profile.model,
            backend_used=active_client.backend_name,
            files_scanned=len(file_contents),
            findings=findings,
            gate_threshold=self.policy.fail_on_severity,
            gate_passed=gate_passed,
            summary_counts=counts,
            scanner_metadata=metadata,
        )

