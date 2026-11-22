"""Deterministic offline heuristic analyzer used when running air-gapped or without a live LLM."""

from __future__ import annotations

import re
from typing import Any

from aiops_auditor.llm.base import BaseLLMClient
from aiops_auditor.models import ModelProfile

TAINT_SIGNAL_RE = re.compile(
    r"(\$_GET|\$_POST|\$_COOKIE|\$_REQUEST|req\.query|req\.body|req\.params|req\.headers|"
    r"userProvided|userInput|userRule|raw_yaml|raw_bytes|filename|payload|request\.)",
    re.IGNORECASE,
)
SAFE_GUARD_RE = re.compile(
    r"(SafeLoader|['\"]?allowed_classes['\"]?\s*=>\s*false|escapeshellarg|execFile\(|"
    r"ObjectInputFilter|SimpleEvaluationContext|parameterized|shell=False)",
    re.IGNORECASE,
)


class HeuristicLLMClient(BaseLLMClient):
    """Rule-assisted taint & remediation fallback with zero GPU/network requirements."""

    def __init__(self, profile: ModelProfile) -> None:
        super().__init__(profile)

    @property
    def backend_name(self) -> str:
        return "heuristic"

    def health_check(self) -> bool:
        return True

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        has_taint = bool(TAINT_SIGNAL_RE.search(user_prompt))
        has_guard = bool(SAFE_GUARD_RE.search(user_prompt))

        sev_match = re.search(r"Initial Severity:\s*(\w+)", user_prompt)
        base_sev = sev_match.group(1).upper() if sev_match else "MEDIUM"

        remed_match = re.search(r"Default Remediation:\s*(.+)", user_prompt)
        default_remed = (
            remed_match.group(1).strip()
            if remed_match
            else "Validate and sanitize untrusted inputs, remove dangerous dynamic sinks, and upgrade vulnerable dependencies."
        )

        if has_guard and not has_taint:
            status = "false_positive"
            confidence = 0.80
            adjusted_severity = "LOW"
            taint_note = (
                "Defensive guard/safe API detected in surrounding context without clear "
                "untrusted input source reaching the sink."
            )
        elif has_taint:
            status = "confirmed"
            confidence = 0.86
            adjusted_severity = base_sev
            taint_note = (
                "Untrusted external input source detected in proximity to the dangerous sink "
                "without an intervening safe API or strict allowlist guard."
            )
        else:
            status = "needs_review"
            confidence = 0.68
            adjusted_severity = base_sev
            taint_note = (
                "Dangerous sink or vulnerable component identified; verify caller dataflow "
                "and runtime reachability with a live <=16GB VRAM LLM profile."
            )

        return {
            "status": status,
            "adjusted_severity": adjusted_severity,
            "confidence": confidence,
            "taint_analysis": taint_note,
            "remediation_summary": default_remed,
            "suggested_patch": "",
        }
