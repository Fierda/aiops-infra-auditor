"""Command-line interface for AIOps Infra Auditor."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from aiops_auditor.agents.change_gate import evaluate_pre_deploy_gate
from aiops_auditor.agents.orchestrator import AIOpsAuditOrchestrator
from aiops_auditor.config import load_model_profiles, load_policy
from aiops_auditor.intel.cve_kb import CVEKnowledgeBase
from aiops_auditor.models import Severity
from aiops_auditor.reporters import (
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)


def _cmd_models(args: argparse.Namespace) -> int:
    default_profile, profiles = load_model_profiles()
    print(f"Default profile: {default_profile}\n")
    header = f"{'PROFILE':<22} {'TIER':<12} {'BACKEND':<14} {'VRAM(GB)':<9} {'LICENSE':<12} MODEL"
    print(header)
    print("-" * len(header))
    for name, prof in profiles.items():
        if args.vram_gb is not None and not prof.fits_vram(args.vram_gb):
            continue
        marker = "*" if name == default_profile else " "
        print(
            f"{marker}{name:<21} {prof.tier:<12} {prof.backend:<14} "
            f"{prof.vram_gb_required:<9.1f} {prof.license:<12} {prof.model}"
        )
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    default_profile, profiles = load_model_profiles()
    chosen_name = args.profile or os.getenv("AIOPS_MODEL_PROFILE") or default_profile
    if chosen_name not in profiles:
        print(
            f"[ERROR] Unknown model profile '{chosen_name}'. Available: {', '.join(profiles.keys())}",
            file=sys.stderr,
        )
        return 2

    profile = profiles[chosen_name]
    policy = load_policy()
    if args.fail_on:
        policy.fail_on_severity = Severity.from_str(args.fail_on)
    if args.enable_osv:
        policy.enable_osv_lookup = True
    if args.auto_sync_cve:
        policy.auto_sync_cve = True
    if args.max_agent_steps is not None:
        policy.max_agent_steps = args.max_agent_steps
    if args.no_autonomous_agent:
        policy.enable_autonomous_agent = False
    if args.max_llm_findings is not None:
        policy.max_llm_findings = args.max_llm_findings

    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Target path does not exist: {target}", file=sys.stderr)
        return 2

    external_sarif = [Path(p) for p in (args.ingest_sarif or [])]
    orchestrator = AIOpsAuditOrchestrator(
        profile=profile,
        policy=policy,
        strict_llm=args.strict_llm,
    )
    report = orchestrator.run_audit(target_path=target, external_sarif_files=external_sarif)

    out_dir = Path(args.out_dir)
    json_path = write_json_report(report, out_dir / "audit-report.json")
    md_path = write_markdown_report(report, out_dir / "audit-report.md")
    sarif_path = write_sarif_report(report, out_dir / "audit-report.sarif")

    print("=== AIOps Infra Auditor Summary ===")
    print(f"Target        : {report.target_path}")
    print(f"Profile       : {report.profile_name} ({report.model_name}, backend={report.backend_used})")
    print(f"Files Scanned : {report.files_scanned}")
    print(
        "Findings      : "
        f"CRITICAL={report.summary_counts['CRITICAL']} "
        f"HIGH={report.summary_counts['HIGH']} "
        f"MEDIUM={report.summary_counts['MEDIUM']} "
        f"LOW={report.summary_counts['LOW']} "
        f"SUPPRESSED_FP={report.summary_counts['SUPPRESSED_FP']}"
    )
    if report.scanner_metadata.get("fallback_notice"):
        print(f"Notice        : {report.scanner_metadata['fallback_notice']}")
    print(f"Policy Gate   : {'PASS' if report.gate_passed else 'FAIL'} (threshold >= {report.gate_threshold.value})")
    print(f"Reports       : {json_path}, {md_path}, {sarif_path}")

    if not report.gate_passed and not args.no_fail:
        return 1
    return 0


def _cmd_gate(args: argparse.Namespace) -> int:
    default_profile, profiles = load_model_profiles()
    chosen_name = args.profile or os.getenv("AIOPS_MODEL_PROFILE") or default_profile
    if chosen_name not in profiles:
        print(
            f"[ERROR] Unknown model profile '{chosen_name}'. Available: {', '.join(profiles.keys())}",
            file=sys.stderr,
        )
        return 2

    profile = profiles[chosen_name]
    policy = load_policy()
    if args.fail_on:
        policy.fail_on_severity = Severity.from_str(args.fail_on)
    if args.enable_osv:
        policy.enable_osv_lookup = True
    if args.auto_sync_cve:
        policy.auto_sync_cve = True
    if args.max_agent_steps is not None:
        policy.max_agent_steps = args.max_agent_steps
    if args.no_autonomous_agent:
        policy.enable_autonomous_agent = False

    repo_root = Path(args.repo)
    if not repo_root.exists():
        print(f"[ERROR] Repository path does not exist: {repo_root}", file=sys.stderr)
        return 2

    decision = evaluate_pre_deploy_gate(
        repo_root=repo_root,
        stage=args.stage,
        profile=profile,
        policy=policy,
        changed_only=args.changed_only,
        base_ref=args.base_ref,
        strict_llm=args.strict_llm,
    )
    report = decision.report

    out_dir = Path(args.out_dir) / f"gate-{args.stage}"
    json_path = write_json_report(report, out_dir / "audit-report.json")
    md_path = write_markdown_report(report, out_dir / "audit-report.md")
    sarif_path = write_sarif_report(report, out_dir / "audit-report.sarif")

    verdict_banner = (
        "ALLOW DEPLOY / CONFIG CHANGE" if decision.allowed else "BLOCK DEPLOY / CONFIG CHANGE"
    )
    print(f"=== AIOps Pre-Deploy Gate [{args.stage.upper()}] ===")
    print(f"Decision      : {verdict_banner}")
    print(f"Scope Mode    : {'git-changed-only' if decision.changed_only else 'full-stage-scope'}")
    print(f"Profile       : {report.profile_name} ({report.model_name}, backend={report.backend_used})")
    print(f"Files Audited : {report.files_scanned}")
    print(
        "Findings      : "
        f"CRITICAL={report.summary_counts['CRITICAL']} "
        f"HIGH={report.summary_counts['HIGH']} "
        f"MEDIUM={report.summary_counts['MEDIUM']} "
        f"LOW={report.summary_counts['LOW']} "
        f"SUPPRESSED_FP={report.summary_counts['SUPPRESSED_FP']}"
    )
    print(f"Reports       : {json_path}, {md_path}, {sarif_path}")

    return 0 if decision.allowed else 1


def _cmd_sync_intel(args: argparse.Namespace) -> int:
    kb = CVEKnowledgeBase(Path(args.kb_path) if args.kb_path else None)
    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else []
    stats = kb.sync_all(
        eco_packages=[],
        nvd_keywords=keywords,
        include_nvd=args.include_nvd,
    )
    print("=== AIOps Live CVE Knowledge Base Sync ===")
    print(f"KB Path       : {kb.kb_path}")
    print(f"Synced At     : {stats.synced_at}")
    print(
        f"Added Entries : CISA_KEV=+{stats.cisa_kev_added} "
        f"OSV=+{stats.osv_added} NVD=+{stats.nvd_added}"
    )
    print(f"Total Entries : {stats.total_entries}")
    if stats.errors:
        print(f"Warnings      : {'; '.join(stats.errors)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aiops-auditor",
        description="Prod-grade AIOps Infra & Application Security Auditor (<=16GB VRAM open-source LLMs).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_models = sub.add_parser("models", help="List available local-test and <=16GB VRAM prod LLM profiles.")
    p_models.add_argument(
        "--vram-gb",
        type=float,
        default=None,
        help="Filter profiles that fit within the specified VRAM budget in GB (e.g., 16).",
    )
    p_models.set_defaults(func=_cmd_models)

    p_scan = sub.add_parser("scan", help="Run full SAST + SCA + IaC + Secret + AI Agent security audit.")
    p_scan.add_argument("--target", required=True, help="Target directory or file to audit.")
    p_scan.add_argument(
        "--profile",
        default=None,
        help="Model profile from models.yaml (e.g., local-dev, prod-16gb-coder, prod-16gb-reasoning, offline-heuristic).",
    )
    p_scan.add_argument("--out-dir", default="reports", help="Directory for JSON, Markdown, and SARIF outputs.")
    p_scan.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Override CI policy gate failure threshold.",
    )
    p_scan.add_argument(
        "--strict-llm",
        action="store_true",
        help="Fail immediately if the selected Ollama/vLLM server is unreachable instead of falling back.",
    )
    p_scan.add_argument(
        "--enable-osv",
        action="store_true",
        help="Enable live OSV.dev batch vulnerability queries for dependency manifests.",
    )
    p_scan.add_argument(
        "--auto-sync-cve",
        action="store_true",
        help="Auto-update local CVE Knowledge Base (CISA KEV + OSV.dev) directly during scan.",
    )
    p_scan.add_argument(
        "--max-agent-steps",
        type=int,
        default=None,
        help="Maximum autonomous ReAct tool-use steps for the AI Investigation Agent (default: 6).",
    )
    p_scan.add_argument(
        "--no-autonomous-agent",
        action="store_true",
        help="Disable multi-step ReAct investigation loop (keep single-shot triage only).",
    )
    p_scan.add_argument(
        "--max-llm-findings",
        type=int,
        default=None,
        help="Maximum number of top findings to send to the AI triage agent.",
    )
    p_scan.add_argument(
        "--ingest-sarif",
        action="append",
        default=[],
        help="Path to external SARIF 2.1.0 report (Semgrep/Trivy/Checkov) to merge into AI triage.",
    )
    p_scan.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0 even when findings violate the policy gate (useful for report-only runs).",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_gate = sub.add_parser(
        "gate",
        help="Blocking Pre-Deploy / Config-Change Gate triggered before IaC, Ansible, or App/Native deploy.",
    )
    p_gate.add_argument(
        "--stage",
        required=True,
        choices=["iac", "ansible", "app", "all"],
        help="Change stage to gate before deployment or server configuration change.",
    )
    p_gate.add_argument("--repo", default=".", help="Repository root containing IaC, Ansible, and App.")
    p_gate.add_argument("--profile", default=None, help="Model profile from models.yaml.")
    p_gate.add_argument("--out-dir", default="reports", help="Output root directory for gate audit trails.")
    p_gate.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Severity threshold that blocks deploy/config change.",
    )
    p_gate.add_argument(
        "--changed-only",
        action="store_true",
        help="Audit only git-modified/untracked files matching the stage.",
    )
    p_gate.add_argument(
        "--base-ref",
        default="HEAD",
        help="Git base ref for --changed-only diff (e.g., origin/main or HEAD).",
    )
    p_gate.add_argument("--strict-llm", action="store_true", help="Require reachable LLM backend.")
    p_gate.add_argument("--enable-osv", action="store_true", help="Enable live OSV.dev CVE checks.")
    p_gate.add_argument(
        "--auto-sync-cve",
        action="store_true",
        help="Auto-refresh local CVE Knowledge Base (CISA KEV + OSV.dev) before gate evaluation.",
    )
    p_gate.add_argument(
        "--max-agent-steps",
        type=int,
        default=None,
        help="Maximum autonomous ReAct tool-use steps for the AI Investigation Agent.",
    )
    p_gate.add_argument(
        "--no-autonomous-agent",
        action="store_true",
        help="Disable multi-step ReAct investigation loop.",
    )
    p_gate.set_defaults(func=_cmd_gate)

    p_sync = sub.add_parser(
        "sync-intel",
        help="Sync latest CVEs & official mitigations (CISA KEV + NVD) into the local CVE Knowledge Base.",
    )
    p_sync.add_argument(
        "--kb-path",
        default=None,
        help="Optional custom path for cve_kb.json (default: auditor/data/cve_kb.json).",
    )
    p_sync.add_argument(
        "--include-nvd",
        action="store_true",
        help="Also query NVD API 2.0 for recent native engine/framework CVEs.",
    )
    p_sync.add_argument(
        "--keywords",
        default="php,node.js,openssl,spring,next.js,log4j",
        help="Comma-separated technology keywords for NVD sync.",
    )
    p_sync.set_defaults(func=_cmd_sync_intel)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))

