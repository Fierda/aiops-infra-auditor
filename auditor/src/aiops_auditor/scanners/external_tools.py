"""External SARIF 2.1.0 ingestion adapter (Semgrep, Trivy, Checkov, Grype)."""

from __future__ import annotations

import json
from pathlib import Path

from aiops_auditor.models import Finding, Severity

SARIF_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def load_external_sarif(sarif_path: Path) -> list[Finding]:
    """Ingest external SARIF 2.1.0 reports so the AI agent can triage and patch them."""
    if not sarif_path.exists():
        return []

    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    for run in data.get("runs", []):
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "external-tool").lower()
        )
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", "EXT-000"))
            level = str(result.get("level", "warning")).lower()
            severity = SARIF_LEVEL_MAP.get(level, Severity.MEDIUM)
            message = str(result.get("message", {}).get("text", "External scanner finding"))

            file_path = "unknown"
            line_no = 1
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = str(phys.get("artifactLocation", {}).get("uri", "unknown"))
                line_no = int(phys.get("region", {}).get("startLine", 1))

            findings.append(
                Finding(
                    rule_id=f"EXT-{tool_name.upper()}-{rule_id}",
                    title=f"[{tool_name}] {rule_id}",
                    category="EXTERNAL",
                    ecosystem=tool_name,
                    vuln_family="external-sarif",
                    severity=severity,
                    file_path=file_path,
                    line=line_no,
                    cwe="CWE-000",
                    description=message,
                    snippet=message,
                    remediation=f"Inspect and remediate finding reported by {tool_name} ({rule_id}).",
                )
            )
    return findings

