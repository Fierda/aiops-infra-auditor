"""Hardcoded secrets & credential detector."""

from __future__ import annotations

import re
from pathlib import Path

from aiops_auditor.models import Finding, Severity

SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "SEC-001",
        "Potential AWS Access Key ID exposed in source",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-002",
        "Private cryptographic key material committed to repository",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "SEC-003",
        "Potential GitHub Personal Access Token exposed",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-004",
        "Hardcoded database connection string with embedded credentials",
        re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^/\s@]{6,}@"
        ),
        Severity.HIGH,
    ),
]


def scan_secrets(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    """Detect exposed keys, tokens, and inline credentials."""
    if file_path.name.endswith(".example"):
        return []

    findings: list[Finding] = []
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        for rule_id, title, pattern, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                redacted = line[: match.start()] + "[REDACTED_SECRET]" + line[match.end() :]
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        category="SECRET",
                        ecosystem="generic",
                        vuln_family="secrets",
                        severity=severity,
                        file_path=rel_path,
                        line=idx,
                        cwe="CWE-798",
                        description="Secret material detected in source or configuration file.",
                        snippet=f"{idx}: {redacted.strip()}",
                        remediation="Revoke and rotate the credential immediately; inject secrets via Vault/AWS Secrets Manager.",
                    )
                )
    return findings

