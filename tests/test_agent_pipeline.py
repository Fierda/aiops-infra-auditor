"""End-to-end tests for the AIOps multi-stage agent orchestrator, reporters, and policy gates."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aiops_auditor.agents.change_gate import evaluate_pre_deploy_gate
from aiops_auditor.agents.orchestrator import AIOpsAuditOrchestrator
from aiops_auditor.config import load_model_profiles, load_policy
from aiops_auditor.llm.base import BaseLLMClient
from aiops_auditor.models import ModelProfile, Severity
from aiops_auditor.reporters import (
    build_sarif_payload,
    render_markdown_report,
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "app" / "samples_for_audit_test"


class MockProdLLMClient(BaseLLMClient):
    """Simulates a <=16GB VRAM open-source LLM returning structured JSON verdicts."""

    def __init__(self, profile: ModelProfile, reachable: bool = True) -> None:
        super().__init__(profile)
        self._reachable = reachable
        self.seen_prompts: list[str] = []

    @property
    def backend_name(self) -> str:
        return "mock-ollama"

    def health_check(self) -> bool:
        return self._reachable

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        self.seen_prompts.append(user_prompt)
        return {
            "status": "confirmed",
            "adjusted_severity": "CRITICAL",
            "confidence": 0.93,
            "taint_analysis": "Untrusted external request data reaches dangerous sink without allowlist validation.",
            "remediation_summary": "Replace dangerous sink with safe parser/parameterized API.",
            "suggested_patch": "- unsafe_call(user_input)\n+ safe_call(validated_input)",
        }


class TestAgentOrchestratorPipeline(unittest.TestCase):
    def test_full_audit_on_fixtures_with_mock_16gb_model(self) -> None:
        _, profiles = load_model_profiles()
        prod_profile = profiles["prod-16gb-coder"]
        policy = load_policy()
        mock_llm = MockProdLLMClient(prod_profile, reachable=True)

        orchestrator = AIOpsAuditOrchestrator(
            profile=prod_profile,
            policy=policy,
            llm_client=mock_llm,
        )
        report = orchestrator.run_audit(FIXTURES_DIR)

        self.assertGreaterEqual(report.files_scanned, 7)
        self.assertGreaterEqual(len(report.findings), 12)
        self.assertFalse(report.gate_passed)
        self.assertEqual(report.backend_used, "mock-ollama")
        self.assertGreater(report.summary_counts["CRITICAL"], 0)

        # Ensure prompt-injection nonce delimiters were applied to every triage prompt
        triage_prompts = [p for p in mock_llm.seen_prompts if "Audit Candidate Metadata:" in p]
        self.assertGreater(len(triage_prompts), 0)
        for prompt in triage_prompts:
            self.assertIn("<UNTRUSTED_CODE_", prompt)

        # Verify SARIF 2.1.0, Markdown, and JSON report generation
        sarif = build_sarif_payload(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)

        md = render_markdown_report(report)
        self.assertIn("AIOps Infra & Application Security Audit Report", md)
        self.assertIn("prod-16gb-coder", md)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            j_path = write_json_report(report, out / "audit-report.json")
            m_path = write_markdown_report(report, out / "audit-report.md")
            s_path = write_sarif_report(report, out / "audit-report.sarif")
            self.assertTrue(j_path.exists())
            self.assertTrue(m_path.exists())
            self.assertTrue(s_path.exists())
            parsed_json = json.loads(j_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed_json["profile_name"], "prod-16gb-coder")

    def test_graceful_fallback_and_strict_llm_mode(self) -> None:
        _, profiles = load_model_profiles()
        prod_profile = profiles["prod-16gb-coder"]
        policy = load_policy()
        unreachable_llm = MockProdLLMClient(prod_profile, reachable=False)

        # Graceful fallback when strict_llm=False
        orch_fallback = AIOpsAuditOrchestrator(
            profile=prod_profile,
            policy=policy,
            llm_client=unreachable_llm,
            strict_llm=False,
        )
        report = orch_fallback.run_audit(FIXTURES_DIR)
        self.assertEqual(report.backend_used, "heuristic")
        self.assertIn("fallback_notice", report.scanner_metadata)

        # Strict mode fails immediately if LLM is unreachable
        orch_strict = AIOpsAuditOrchestrator(
            profile=prod_profile,
            policy=policy,
            llm_client=unreachable_llm,
            strict_llm=True,
        )
        with self.assertRaises(RuntimeError):
            orch_strict.run_audit(FIXTURES_DIR)

    def test_main_repository_passes_policy_gate(self) -> None:
        _, profiles = load_model_profiles()
        policy = load_policy()
        policy.fail_on_severity = Severity.HIGH

        orchestrator = AIOpsAuditOrchestrator(
            profile=profiles["offline-heuristic"],
            policy=policy,
        )
        report = orchestrator.run_audit(REPO_ROOT)
        self.assertTrue(
            report.gate_passed,
            f"Hardened repo should pass policy gate, but found: {[f.to_dict() for f in report.findings]}",
        )

    def test_pre_deploy_gates_for_iac_ansible_and_app(self) -> None:
        _, profiles = load_model_profiles()
        policy = load_policy()

        for stage in ("iac", "ansible", "app"):
            decision = evaluate_pre_deploy_gate(
                repo_root=REPO_ROOT,
                stage=stage,
                profile=profiles["offline-heuristic"],
                policy=policy,
                changed_only=False,
            )
            self.assertTrue(
                decision.allowed,
                f"Pre-deploy gate '{stage}' should pass on hardened repo: "
                f"{[f.to_dict() for f in decision.report.findings]}",
            )
            self.assertGreater(decision.report.files_scanned, 0)


if __name__ == "__main__":
    unittest.main()

