"""Tests for the Live Self-Updating CVE Knowledge Base & Autonomous ReAct Investigation Agent."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from aiops_auditor.agents.investigator import AutonomousSecurityInvestigator
from aiops_auditor.agents.orchestrator import AIOpsAuditOrchestrator
from aiops_auditor.config import load_model_profiles, load_policy
from aiops_auditor.intel.cve_kb import CVEEntry, CVEKnowledgeBase
from aiops_auditor.llm.base import BaseLLMClient
from aiops_auditor.models import ModelProfile
from aiops_auditor.scanners.sca_deps import scan_dependency_manifest


class ScriptedReActLLM(BaseLLMClient):
    """Simulates a <=16GB VRAM open-source LLM running a multi-step ReAct investigation."""

    def __init__(self, profile: ModelProfile) -> None:
        super().__init__(profile)
        self.turn = 0
        self.seen_observations: list[str] = []

    @property
    def backend_name(self) -> str:
        return "mock-react-ollama"

    def health_check(self) -> bool:
        return True

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        # Single-shot triage call
        if "Audit Candidate Metadata:" in user_prompt:
            return {
                "status": "confirmed",
                "adjusted_severity": "HIGH",
                "confidence": 0.9,
                "taint_analysis": "Confirmed candidate taint path.",
                "remediation_summary": "Apply input allowlist.",
                "suggested_patch": "",
            }

        # Multi-step ReAct investigation calls
        self.seen_observations.append(user_prompt)
        self.turn += 1
        if self.turn == 1:
            return {
                "thought": "Inspect auth middleware and check recent CVEs for next/express.",
                "tool": "read_code_slice",
                "args": {"file": "auth_middleware.js", "start_line": 1, "end_line": 30},
            }
        if self.turn == 2:
            return {
                "thought": "Check who calls verifyAdminHeader across the repo.",
                "tool": "grep_symbol",
                "args": {"symbol": "verifyAdminHeader"},
            }
        if self.turn == 3:
            return {
                "thought": "Query live CVE Knowledge Base for newly synced Next.js middleware bypass.",
                "tool": "lookup_cve_intel",
                "args": {"query": "next middleware"},
            }
        if self.turn == 4:
            return {
                "thought": "Auth middleware trusts client-supplied x-internal-admin header without signature.",
                "tool": "report_finding",
                "args": {
                    "title": "Trusting spoofable x-internal-admin header bypasses admin authorization",
                    "file": "auth_middleware.js",
                    "line": 4,
                    "ecosystem": "nodejs",
                    "severity": "CRITICAL",
                    "cwe": "CWE-287",
                    "cve": "CVE-2025-29927",
                    "taint_analysis": "Client-controlled header x-internal-admin grants admin role directly.",
                    "remediation_summary": "Verify signed JWT/mTLS claims and strip internal headers at ingress.",
                    "suggested_patch": "- if (req.headers['x-internal-admin'] === 'true') return next();\n+ if (verifySignedAdminToken(req)) return next();",
                },
            }
        return {
            "thought": "Investigation complete.",
            "tool": "finish",
            "args": {"summary": "Found critical header-spoofing auth bypass beyond static regex rules."},
        }


class TestLiveCVEKBAndAutonomousAgent(unittest.TestCase):
    def test_cve_kb_syncs_cisa_osv_nvd_and_flags_new_zero_day(self) -> None:
        fake_cisa = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-99999",
                    "vendorProject": "Acme",
                    "product": "FastParser",
                    "vulnerabilityName": "Acme FastParser Heap Buffer Overflow",
                    "shortDescription": "Remote memory corruption in C parser.",
                    "requiredAction": "Upgrade Acme FastParser to >= 2.4.1 immediately.",
                    "dateAdded": "2026-11-20",
                    "dueDate": "2026-12-01",
                    "cwes": ["CWE-787"],
                }
            ]
        }
        fake_osv_batch = {"results": [{"vulns": [{"id": "GHSA-2026-abcd"}]}]}
        fake_osv_detail = {
            "id": "GHSA-2026-abcd",
            "summary": "Zero-day RCE in brand-new-oss-lib before 1.2.5",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}]}],
            "references": [{"url": "https://osv.dev/vulnerability/GHSA-2026-abcd"}],
        }

        with tempfile.TemporaryDirectory() as tmp:
            kb_file = Path(tmp) / "cve_kb.json"
            kb = CVEKnowledgeBase(kb_path=kb_file)

            with (
                patch("aiops_auditor.intel.cve_kb._http_get_json") as mock_get,
                patch("aiops_auditor.intel.cve_kb._http_post_json") as mock_post,
            ):
                mock_get.side_effect = [fake_cisa, fake_osv_detail]
                mock_post.return_value = fake_osv_batch

                stats = kb.sync_all(
                    eco_packages=[("npm", "brand-new-oss-lib", "1.2.0")],
                    include_nvd=False,
                )

            self.assertEqual(stats.cisa_kev_added, 1)
            self.assertEqual(stats.osv_added, 1)
            self.assertTrue(kb_file.exists())

            # Reload from disk (verifies persistence for offline/air-gapped use)
            reloaded = CVEKnowledgeBase(kb_path=kb_file)
            kev_hits = reloaded.search("CVE-2026-99999")
            self.assertEqual(len(kev_hits), 1)
            self.assertTrue(kev_hits[0].actively_exploited)
            self.assertIn("2.4.1", kev_hits[0].mitigation)

            # Verify SCA scanner catches the brand-new synced CVE on vulnerable version
            vuln_pkg = '{"dependencies": {"brand-new-oss-lib": "1.2.0"}}'
            findings_vuln = scan_dependency_manifest(
                Path("package.json"), "package.json", vuln_pkg, cve_kb=reloaded
            )
            self.assertTrue(any(f.cve == "GHSA-2026-abcd" for f in findings_vuln))

            # Verify patched version (>= 1.2.5) is NOT flagged
            safe_pkg = '{"dependencies": {"brand-new-oss-lib": "1.2.5"}}'
            findings_safe = scan_dependency_manifest(
                Path("package.json"), "package.json", safe_pkg, cve_kb=reloaded
            )
            self.assertFalse(any(f.cve == "GHSA-2026-abcd" for f in findings_safe))

    def test_autonomous_react_agent_discovers_logic_bug_beyond_regex(self) -> None:
        _, profiles = load_model_profiles()
        prod_profile = profiles["prod-16gb-coder"]
        policy = load_policy()
        policy.enable_autonomous_agent = True
        policy.max_agent_steps = 6
        policy.auto_sync_cve = False

        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            # A subtle business-logic auth bypass that NO static regex rule catches!
            (repo_dir / "auth_middleware.js").write_text(
                "function verifyAdminHeader(req, res, next) {\n"
                "  // Logic flaw: trusting client header directly\n"
                "  if (req.headers['x-internal-admin'] === 'true') {\n"
                "    return next();\n"
                "  }\n"
                "  return res.status(403).json({ error: 'forbidden' });\n"
                "}\n"
                "module.exports = { verifyAdminHeader };\n",
                encoding="utf-8",
            )
            (repo_dir / "routes.js").write_text(
                "const { verifyAdminHeader } = require('./auth_middleware');\n"
                "app.post('/admin/reset', verifyAdminHeader, (req, res) => res.json({ ok: true }));\n",
                encoding="utf-8",
            )

            kb = CVEKnowledgeBase(kb_path=repo_dir / "kb.json")
            react_llm = ScriptedReActLLM(prod_profile)
            orchestrator = AIOpsAuditOrchestrator(
                profile=prod_profile,
                policy=policy,
                llm_client=react_llm,
                cve_kb=kb,
            )
            report = orchestrator.run_audit(repo_dir)

            # Static regex found 0 issues, yet Autonomous ReAct Agent discovered the CRITICAL auth bypass!
            agent_findings = [f for f in report.findings if f.category == "AI_AGENT"]
            self.assertEqual(len(agent_findings), 1)
            self.assertEqual(agent_findings[0].effective_severity.value, "CRITICAL")
            self.assertEqual(agent_findings[0].cwe, "CWE-287")
            self.assertFalse(report.gate_passed)

            # Verify multi-step tool trace & anti-prompt-injection delimiters on code slices
            inv_meta = report.scanner_metadata["autonomous_agent"]
            self.assertEqual(inv_meta["steps_executed"], 5)
            self.assertEqual(inv_meta["discovered_count"], 1)
            self.assertTrue(any("<UNTRUSTED_CODE_" in obs for obs in react_llm.seen_observations))
            self.assertTrue(any("CVE-2025-29927" in obs for obs in react_llm.seen_observations))


if __name__ == "__main__":
    unittest.main()

