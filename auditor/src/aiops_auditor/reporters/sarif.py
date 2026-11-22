"""SARIF 2.1.0 exporter for GitHub Code Scanning & GitLab Security Dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aiops_auditor import __version__
from aiops_auditor.models import AuditReport, Severity


def _severity_to_sarif_level(sev: Severity) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def build_sarif_payload(report: AuditReport) -> dict[str, Any]:
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        if finding.is_suppressed_false_positive:
            continue

        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {
                    "text": finding.remediation,
                },
                "properties": {
                    "cwe": finding.cwe,
                    "ecosystem": finding.ecosystem,
                    "category": finding.category,
                    "vuln_family": finding.vuln_family,
                },
            }

        taint_note = (
            f" | AI Triage ({finding.verdict.status}, conf={finding.verdict.confidence:.2f}): "
            f"{finding.verdict.taint_analysis}"
            if finding.verdict
            else ""
        )

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _severity_to_sarif_level(finding.effective_severity),
                "message": {
                    "text": f"{finding.title} ({finding.cwe}){taint_note}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                            },
                        }
                    }
                ],
                "properties": {
                    "effective_severity": finding.effective_severity.value,
                    "cve": finding.cve,
                    "remediation": (
                        finding.verdict.remediation_summary
                        if finding.verdict and finding.verdict.remediation_summary
                        else finding.remediation
                    ),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIOps-Infra-Auditor",
                        "version": __version__,
                        "informationUri": "https://github.com/local/aiops-infra-auditor",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(report: AuditReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_sarif_payload(report)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path

