"""Machine-readable JSON report writer for AIOps/SIEM/S3 integration."""

from __future__ import annotations

import json
from pathlib import Path

from aiops_auditor.models import AuditReport


def write_json_report(report: AuditReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path

