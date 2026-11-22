"""Tests for model profile configuration, <=16GB VRAM constraints, and LLM JSON parsing."""

from __future__ import annotations

import unittest

from aiops_auditor.config import load_model_profiles, load_policy
from aiops_auditor.llm.base import extract_json_object
from aiops_auditor.models import Severity


class TestModelsAndConfig(unittest.TestCase):
    def test_load_model_profiles_and_vram_budget(self) -> None:
        default_name, profiles = load_model_profiles()
        self.assertEqual(default_name, "local-dev")
        self.assertIn("local-tiny", profiles)
        self.assertIn("local-dev", profiles)
        self.assertIn("prod-16gb-coder", profiles)
        self.assertIn("prod-16gb-reasoning", profiles)
        self.assertIn("prod-16gb-vllm", profiles)
        self.assertIn("offline-heuristic", profiles)

        # Verify all prod models strictly fit within <= 16GB VRAM and are open-source
        prod_profiles = [p for p in profiles.values() if p.tier == "prod_16gb"]
        self.assertGreaterEqual(len(prod_profiles), 3)
        for prof in prod_profiles:
            self.assertTrue(
                prof.fits_vram(16.0),
                f"Prod profile {prof.name} requires {prof.vram_gb_required}GB (> 16GB VRAM)",
            )
            self.assertIn(prof.license, {"Apache-2.0", "MIT"})

        # Verify local-dev is lightweight for laptop CPU/small GPU tests
        self.assertLessEqual(profiles["local-dev"].vram_gb_required, 4.0)

    def test_load_policy_defaults(self) -> None:
        policy = load_policy()
        self.assertEqual(policy.fail_on_severity, Severity.HIGH)
        self.assertIn("samples_for_audit_test", policy.excluded_dirs)
        self.assertGreater(policy.max_llm_findings, 0)

    def test_extract_json_strips_deepseek_think_and_fences(self) -> None:
        raw = (
            "<think>\nChecking source to sink taint path...\n</think>\n"
            "```json\n"
            '{"status": "confirmed", "adjusted_severity": "CRITICAL", "confidence": 0.94}\n'
            "```"
        )
        parsed = extract_json_object(raw)
        self.assertEqual(parsed["status"], "confirmed")
        self.assertEqual(parsed["adjusted_severity"], "CRITICAL")
        self.assertAlmostEqual(parsed["confidence"], 0.94)


if __name__ == "__main__":
    unittest.main()

