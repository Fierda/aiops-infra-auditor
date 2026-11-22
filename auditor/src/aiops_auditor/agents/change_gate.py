"""Pre-Deploy & Configuration-Change Gatekeeper for IaC, Ansible, and App/Native Engine rollouts."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from aiops_auditor.agents.orchestrator import AIOpsAuditOrchestrator
from aiops_auditor.models import AuditPolicy, AuditReport, ModelProfile

STAGE_SCOPE_DIRS: dict[str, list[str]] = {
    "iac": ["infra", "k8s", "docker-compose.yml"],
    "ansible": ["ansible"],
    "app": ["app", "src", "native", "engine"],
    "all": ["."],
}


@dataclass
class GateDecision:
    stage: str
    allowed: bool
    changed_only: bool
    triggered_files: list[str]
    report: AuditReport


def detect_git_changed_files(repo_root: Path, base_ref: str = "HEAD") -> list[Path]:
    """Return modified/untracked files relative to base_ref for targeted pre-deploy audits."""
    changed: list[Path] = []
    try:
        diff_proc = subprocess.run(
            ["git", "diff", "--name-only", base_ref],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        untracked_proc = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        raw_paths = (
            diff_proc.stdout.splitlines() + untracked_proc.stdout.splitlines()
        )
        for rel in sorted(set(p.strip() for p in raw_paths if p.strip())):
            candidate = (repo_root / rel).resolve()
            if candidate.exists() and candidate.is_file():
                changed.append(candidate)
    except (OSError, subprocess.SubprocessError):
        return []
    return changed


def classify_stage_for_path(rel_posix: str) -> str:
    """Classify a changed file into its deployment gate stage: iac | ansible | app."""
    lower = rel_posix.lower()
    if (
        lower.startswith(("infra/", "k8s/", "terraform/", "helm/"))
        or lower.endswith(".tf")
        or "docker-compose" in lower
    ):
        return "iac"
    if lower.startswith("ansible/") or "/playbooks/" in lower or "/roles/" in lower:
        return "ansible"
    return "app"


def collect_stage_files(
    repo_root: Path,
    stage: str,
    policy: AuditPolicy,
    changed_only: bool = False,
    base_ref: str = "HEAD",
) -> list[Path]:
    """Collect the exact files to audit before allowing a deploy or config change."""
    resolved_root = repo_root.resolve()
    excluded = set(policy.excluded_dirs)

    if changed_only:
        git_files = detect_git_changed_files(resolved_root, base_ref=base_ref)
        filtered: list[Path] = []
        for fpath in git_files:
            try:
                rel = fpath.relative_to(resolved_root).as_posix()
            except ValueError:
                continue
            if any(part in excluded for part in Path(rel).parts):
                continue
            if stage == "all" or classify_stage_for_path(rel) == stage:
                filtered.append(fpath)
        return filtered

    if stage == "all":
        return []  # Empty means orchestrator walks entire repo_root

    stage_files: list[Path] = []
    for rel_entry in STAGE_SCOPE_DIRS.get(stage, ["."]):
        candidate = resolved_root / rel_entry
        if not candidate.exists():
            continue
        if candidate.is_file():
            stage_files.append(candidate)
        else:
            for item in sorted(candidate.rglob("*")):
                if not item.is_file():
                    continue
                rel_parts = item.relative_to(resolved_root).parts
                if any(part in excluded for part in rel_parts):
                    continue
                stage_files.append(item)
    return stage_files


def evaluate_pre_deploy_gate(
    repo_root: Path,
    stage: str,
    profile: ModelProfile,
    policy: AuditPolicy,
    changed_only: bool = False,
    base_ref: str = "HEAD",
    strict_llm: bool = False,
) -> GateDecision:
    """Run the AIOps Security Auditor as a blocking Pre-Deploy / Config-Change Gate."""
    orchestrator = AIOpsAuditOrchestrator(
        profile=profile,
        policy=policy,
        strict_llm=strict_llm,
    )
    stage_files = collect_stage_files(
        repo_root=repo_root,
        stage=stage,
        policy=policy,
        changed_only=changed_only,
        base_ref=base_ref,
    )

    # If changed_only=False and stage == "all", pass explicit_files=None to scan full repo
    explicit = None if (stage == "all" and not changed_only) else stage_files
    report = orchestrator.run_audit(target_path=repo_root, explicit_files=explicit)
    report.scanner_metadata["gate_stage"] = stage
    report.scanner_metadata["changed_only"] = changed_only

    triggered = [
        f.relative_to(repo_root.resolve()).as_posix()
        for f in stage_files
        if f.exists()
    ]
    return GateDecision(
        stage=stage,
        allowed=report.gate_passed,
        changed_only=changed_only,
        triggered_files=triggered,
        report=report,
    )

