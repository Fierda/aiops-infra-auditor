"""Core data structures for findings, model profiles, verdicts, and audit reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        normalized = (value or "MEDIUM").strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.MEDIUM


@dataclass(frozen=True)
class ModelProfile:
    name: str
    tier: str
    backend: str
    model: str
    license: str
    vram_gb_required: float
    ram_gb_required: float
    context_window: int
    temperature: float
    timeout_sec: int
    description: str

    def fits_vram(self, available_vram_gb: float) -> bool:
        return self.vram_gb_required <= available_vram_gb


@dataclass
class AuditPolicy:
    fail_on_severity: Severity = Severity.HIGH
    max_llm_findings: int = 25
    context_lines_before: int = 18
    context_lines_after: int = 18
    enable_osv_lookup: bool = False
    auto_sync_cve: bool = False
    cve_kb_ttl_hours: int = 6
    enable_autonomous_agent: bool = True
    max_agent_steps: int = 6
    excluded_dirs: list[str] = field(
        default_factory=lambda: [
            ".git",
            ".terraform",
            "node_modules",
            "vendor",
            ".venv",
            "venv",
            "__pycache__",
            "dist",
            "build",
            "reports",
        ]
    )
    allowed_false_positive_suppression: bool = True


@dataclass
class LLMVerdict:
    status: str  # confirmed | needs_review | false_positive
    adjusted_severity: Severity
    confidence: float
    taint_analysis: str
    remediation_summary: str
    suggested_patch: str = ""
    model_used: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["adjusted_severity"] = self.adjusted_severity.value
        return data


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str  # SAST | SCA | IAC | SECRET | EXTERNAL
    ecosystem: str  # php | nodejs | java | python | terraform | ansible | docker | generic
    severity: Severity
    file_path: str
    line: int
    cwe: str
    description: str
    snippet: str
    remediation: str
    cve: str = ""
    vuln_family: str = ""  # e.g., php2shell, node2shell, java4shell, iac-hardening
    taint_sources: list[str] = field(default_factory=list)
    related_symbols: list[str] = field(default_factory=list)
    verdict: LLMVerdict | None = None

    @property
    def effective_severity(self) -> Severity:
        if self.verdict is not None:
            return self.verdict.adjusted_severity
        return self.severity

    @property
    def is_suppressed_false_positive(self) -> bool:
        return (
            self.verdict is not None
            and self.verdict.status == "false_positive"
            and self.verdict.confidence >= 0.75
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "ecosystem": self.ecosystem,
            "severity": self.severity.value,
            "effective_severity": self.effective_severity.value,
            "file_path": self.file_path,
            "line": self.line,
            "cwe": self.cwe,
            "cve": self.cve,
            "vuln_family": self.vuln_family,
            "description": self.description,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "taint_sources": self.taint_sources,
            "related_symbols": self.related_symbols,
            "verdict": self.verdict.to_dict() if self.verdict else None,
        }


@dataclass
class AuditReport:
    target_path: str
    generated_at: str
    profile_name: str
    model_name: str
    backend_used: str
    files_scanned: int
    findings: list[Finding]
    gate_threshold: Severity
    gate_passed: bool
    summary_counts: dict[str, int]
    scanner_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_path": self.target_path,
            "generated_at": self.generated_at,
            "profile_name": self.profile_name,
            "model_name": self.model_name,
            "backend_used": self.backend_used,
            "files_scanned": self.files_scanned,
            "gate_threshold": self.gate_threshold.value,
            "gate_passed": self.gate_passed,
            "summary_counts": self.summary_counts,
            "scanner_metadata": self.scanner_metadata,
            "findings": [f.to_dict() for f in self.findings],
        }

