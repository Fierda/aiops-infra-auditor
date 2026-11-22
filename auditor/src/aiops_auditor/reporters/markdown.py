"""Executive & developer-friendly Markdown audit report generator."""

from __future__ import annotations

from pathlib import Path

from aiops_auditor.models import AuditReport


def render_markdown_report(report: AuditReport) -> str:
    gate_badge = "PASS" if report.gate_passed else "FAIL"
    lines: list[str] = [
        "# AIOps Infra & Application Security Audit Report",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| **Target** | `{report.target_path}` |",
        f"| **Generated At (UTC)** | `{report.generated_at}` |",
        f"| **Model Profile** | `{report.profile_name}` (`{report.model_name}`) |",
        f"| **Active Backend** | `{report.backend_used}` |",
        f"| **Files Scanned** | `{report.files_scanned}` |",
        f"| **Policy Gate (`>= {report.gate_threshold.value}`)** | **{gate_badge}** |",
        "",
    ]

    fallback_notice = report.scanner_metadata.get("fallback_notice")
    if fallback_notice:
        lines.append(f"> **Notice:** {fallback_notice}")
        lines.append("")

    kb_entries = report.scanner_metadata.get("cve_kb_entries")
    kb_synced = report.scanner_metadata.get("cve_kb_last_synced")
    if kb_entries is not None:
        lines.extend(
            [
                "## Live CVE Knowledge Base & Autonomous Agent",
                "",
                f"- **CVE Knowledge Base:** `{kb_entries}` entries (last synced: `{kb_synced}`)",
            ]
        )
        sync_info = report.scanner_metadata.get("cve_kb_sync")
        if isinstance(sync_info, dict):
            lines.append(
                f"- **Auto-Sync Delta:** CISA KEV `+{sync_info.get('cisa_kev_added', 0)}`, "
                f"OSV.dev `+{sync_info.get('osv_added', 0)}`, "
                f"NVD `+{sync_info.get('nvd_added', 0)}`"
            )
        agent_info = report.scanner_metadata.get("autonomous_agent")
        if isinstance(agent_info, dict):
            lines.append(
                f"- **Autonomous ReAct Agent:** `{agent_info.get('steps_executed', 0)}` steps executed, "
                f"`{agent_info.get('discovered_count', 0)}` extra finding(s) discovered"
            )
            if agent_info.get("summary"):
                lines.append(f"- **Agent Summary:** {agent_info['summary']}")
        lines.append("")

    lines.extend(
        [
            "## Summary by Severity",
            "",
            "| CRITICAL | HIGH | MEDIUM | LOW | INFO | Suppressed FP |",
            "| :---: | :---: | :---: | :---: | :---: | :---: |",
            (
                f"| {report.summary_counts.get('CRITICAL', 0)} "
                f"| {report.summary_counts.get('HIGH', 0)} "
                f"| {report.summary_counts.get('MEDIUM', 0)} "
                f"| {report.summary_counts.get('LOW', 0)} "
                f"| {report.summary_counts.get('INFO', 0)} "
                f"| {report.summary_counts.get('SUPPRESSED_FP', 0)} |"
            ),
            "",
            "## Findings Detail",
            "",
        ]
    )

    if not report.findings:
        lines.append("No security findings detected across SAST, SCA, IaC, and Secret scanners.")
        return "\n".join(lines) + "\n"

    for idx, finding in enumerate(report.findings, start=1):
        status_str = finding.verdict.status.upper() if finding.verdict else "STATIC"
        conf_str = f"{finding.verdict.confidence:.2f}" if finding.verdict else "N/A"
        lines.extend(
            [
                f"### {idx}. [{finding.effective_severity.value}] {finding.title}",
                "",
                f"- **Rule:** `{finding.rule_id}` | **Category:** `{finding.category}` | "
                f"**Ecosystem:** `{finding.ecosystem}` | **Family:** `{finding.vuln_family or 'general'}`",
                f"- **Location:** `{finding.file_path}:{finding.line}`",
                f"- **CWE / CVE:** `{finding.cwe}` / `{finding.cve or 'N/A'}`",
                f"- **AI Agent Verdict:** `{status_str}` (confidence: `{conf_str}`)",
                "",
                "**Snippet:**",
                "```",
                finding.snippet,
                "```",
                "",
            ]
        )
        if finding.verdict and finding.verdict.taint_analysis:
            lines.append(f"**AI Taint & Reachability Analysis:** {finding.verdict.taint_analysis}")
            lines.append("")

        remediation_text = (
            finding.verdict.remediation_summary
            if finding.verdict and finding.verdict.remediation_summary
            else finding.remediation
        )
        lines.append(f"**Defensive Remediation:** {remediation_text}")
        lines.append("")

        if finding.verdict and finding.verdict.suggested_patch:
            lines.extend(
                [
                    "**Suggested Patch:**",
                    "```diff",
                    finding.verdict.suggested_patch,
                    "```",
                    "",
                ]
            )

    return "\n".join(lines) + "\n"


def write_markdown_report(report: AuditReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown_report(report), encoding="utf-8")
    return output_path

