"""Self-updating local CVE Knowledge Base syncing CISA KEV, OSV.dev, and NVD API 2.0.

Allows local open-source LLMs (3B/14B <=16GB VRAM) to reason over brand-new CVEs
and exact vendor mitigations without retraining weights or checking blogs manually.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aiops_auditor.models import Severity

DEFAULT_KB_PATH = Path(__file__).resolve().parents[3] / "data" / "cve_kb.json"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEEntry:
    cve_id: str
    source: str  # cisa_kev | osv | nvd | curated
    ecosystem: str  # npm | maven | composer | pypi | c_cpp | generic
    package: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    summary: str
    mitigation: str
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    actively_exploited: bool = False
    cwe: str = "CWE-1104"
    published_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CVEEntry":
        return cls(
            cve_id=str(data.get("cve_id", "")),
            source=str(data.get("source", "curated")),
            ecosystem=str(data.get("ecosystem", "generic")),
            package=str(data.get("package", "")),
            severity=str(data.get("severity", "HIGH")).upper(),
            title=str(data.get("title", "")),
            summary=str(data.get("summary", "")),
            mitigation=str(data.get("mitigation", "")),
            fixed_versions=[str(v) for v in data.get("fixed_versions", [])],
            references=[str(r) for r in data.get("references", [])],
            actively_exploited=bool(data.get("actively_exploited", False)),
            cwe=str(data.get("cwe", "CWE-1104")),
            published_at=str(data.get("published_at", "")),
            updated_at=str(data.get("updated_at", "")),
        )


@dataclass
class SyncStats:
    synced_at: str
    cisa_kev_added: int = 0
    osv_added: int = 0
    nvd_added: int = 0
    total_entries: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _http_get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 12) -> Any:
    req_headers = {"User-Agent": "aiops-infra-auditor/1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_json(
    url: str, payload: dict[str, Any], headers: dict[str, str] | None = None, timeout: int = 12
) -> Any:
    req_headers = {
        "User-Agent": "aiops-infra-auditor/1.0",
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=req_headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _parse_ver_tuple(raw_ver: str) -> tuple[int, ...] | None:
    cleaned = re.sub(r"^[^0-9]*", "", raw_ver.strip())
    m = re.match(r"(\d+(?:\.\d+)*)", cleaned)
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _seed_baseline_entries() -> list[CVEEntry]:
    """Curated high-impact open-source baseline (available even 100% air-gapped)."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        CVEEntry(
            cve_id="CVE-2025-55182",
            source="curated",
            ecosystem="npm",
            package="react-server-dom-webpack",
            severity="CRITICAL",
            title="React Server Components Flight Protocol Unsafe Deserialization (React2Shell)",
            summary="Untrusted Flight payloads can execute arbitrary server-side code on vulnerable RSC runtimes.",
            mitigation="Upgrade react-server-dom-* to >= 19.0.1 / 19.1.2 / 19.2.1 and patched Next.js release; restrict exposed Server Action endpoints.",
            fixed_versions=["19.0.1"],
            actively_exploited=True,
            cwe="CWE-502",
            updated_at=now,
        ),
        CVEEntry(
            cve_id="CVE-2025-29927",
            source="curated",
            ecosystem="npm",
            package="next",
            severity="CRITICAL",
            title="Next.js Middleware Authorization Bypass",
            summary="Crafted internal x-middleware-subrequest headers can bypass Next.js authentication middleware.",
            mitigation="Upgrade Next.js to >= 15.2.3 (or 14.2.25) and strip external x-middleware-subrequest headers at reverse proxy/WAF.",
            fixed_versions=["15.2.3"],
            actively_exploited=True,
            cwe="CWE-287",
            updated_at=now,
        ),
        CVEEntry(
            cve_id="CVE-2021-44228",
            source="curated",
            ecosystem="maven",
            package="org.apache.logging.log4j:log4j-core",
            severity="CRITICAL",
            title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
            summary="JNDI lookup substitution in log messages permits remote code execution.",
            mitigation="Upgrade log4j-core to >= 2.17.1 and remove JndiLookup class from legacy classpaths.",
            fixed_versions=["2.17.1"],
            actively_exploited=True,
            cwe="CWE-917",
            updated_at=now,
        ),
        CVEEntry(
            cve_id="CVE-2022-22965",
            source="curated",
            ecosystem="maven",
            package="org.springframework:spring-beans",
            severity="CRITICAL",
            title="Spring Framework ClassLoader Manipulation RCE (Spring4Shell)",
            summary="Data binding on JDK 9+ exposes ClassLoader properties leading to RCE.",
            mitigation="Upgrade Spring Framework to >= 5.3.18 / 5.2.20 and explicitly set disallowedFields on WebDataBinder.",
            fixed_versions=["5.3.18"],
            actively_exploited=True,
            cwe="CWE-94",
            updated_at=now,
        ),
        CVEEntry(
            cve_id="CVE-2024-4577",
            source="curated",
            ecosystem="c_cpp",
            package="php",
            severity="CRITICAL",
            title="PHP-CGI Argument Injection Remote Code Execution (php2shell class)",
            summary="Best-fit character encoding in PHP-CGI on Windows allows argument injection into the PHP C engine.",
            mitigation="Upgrade PHP to >= 8.3.8 / 8.2.20 / 8.1.29 and migrate from PHP-CGI to PHP-FPM.",
            fixed_versions=["8.3.8"],
            actively_exploited=True,
            cwe="CWE-78",
            updated_at=now,
        ),
    ]


class CVEKnowledgeBase:
    """Persistent local vulnerability knowledge base with live CISA KEV + OSV + NVD sync."""

    def __init__(self, kb_path: Path | None = None) -> None:
        self.kb_path = kb_path or DEFAULT_KB_PATH
        self.last_synced_at: str = ""
        self.entries: dict[str, CVEEntry] = {}
        self.load()

    def load(self) -> None:
        if self.kb_path.exists():
            try:
                raw = json.loads(self.kb_path.read_text(encoding="utf-8"))
                self.last_synced_at = str(raw.get("last_synced_at", ""))
                for item in raw.get("entries", []):
                    entry = CVEEntry.from_dict(item)
                    if entry.cve_id:
                        self.entries[self._entry_key(entry)] = entry
            except (OSError, json.JSONDecodeError):
                pass

        # Ensure baseline entries are always present
        for seed in _seed_baseline_entries():
            key = self._entry_key(seed)
            if key not in self.entries:
                self.entries[key] = seed

    def save(self) -> Path:
        self.kb_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1.0",
            "last_synced_at": self.last_synced_at,
            "entry_count": len(self.entries),
            "entries": [e.to_dict() for e in sorted(self.entries.values(), key=lambda x: x.cve_id)],
        }
        self.kb_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return self.kb_path

    @staticmethod
    def _entry_key(entry: CVEEntry) -> str:
        return f"{entry.cve_id.upper()}::{entry.ecosystem.lower()}::{entry.package.lower()}"

    def upsert(self, entry: CVEEntry) -> bool:
        """Insert or update an entry; returns True if newly added."""
        key = self._entry_key(entry)
        is_new = key not in self.entries
        existing = self.entries.get(key)
        if existing:
            # Preserve actively_exploited flag and richest mitigation
            entry.actively_exploited = entry.actively_exploited or existing.actively_exploited
            if not entry.fixed_versions and existing.fixed_versions:
                entry.fixed_versions = existing.fixed_versions
            if len(existing.mitigation) > len(entry.mitigation):
                entry.mitigation = existing.mitigation
        self.entries[key] = entry
        return is_new

    def is_stale(self, ttl_hours: int = 6) -> bool:
        if not self.last_synced_at:
            return True
        try:
            ts = datetime.fromisoformat(self.last_synced_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) - ts > timedelta(hours=ttl_hours)
        except ValueError:
            return True

    def sync_cisa_kev(self, max_recent: int = 250) -> int:
        """Sync CISA Known Exploited Vulnerabilities catalog + official requiredAction mitigations."""
        data = _http_get_json(CISA_KEV_URL)
        vulns = data.get("vulnerabilities", [])
        # Keep the most recent actively exploited entries to stay fast & relevant
        recent_vulns = sorted(
            vulns, key=lambda v: str(v.get("dateAdded", "")), reverse=True
        )[:max_recent]

        added = 0
        now = datetime.now(timezone.utc).isoformat()
        for item in recent_vulns:
            cve_id = str(item.get("cveID", "")).strip()
            if not cve_id:
                continue
            vendor = str(item.get("vendorProject", "")).strip()
            product = str(item.get("product", "")).strip()
            pkg = f"{vendor}/{product}".strip("/").lower() or "generic"
            mitigation = str(item.get("requiredAction", "")).strip()
            due = str(item.get("dueDate", "")).strip()
            if due:
                mitigation = f"{mitigation} (CISA KEV due: {due})".strip()

            entry = CVEEntry(
                cve_id=cve_id,
                source="cisa_kev",
                ecosystem="generic",
                package=pkg,
                severity="CRITICAL",
                title=str(item.get("vulnerabilityName", cve_id)),
                summary=str(item.get("shortDescription", "")),
                mitigation=mitigation or "Apply vendor security updates immediately per CISA KEV.",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                actively_exploited=True,
                cwe=(item.get("cwes") or ["CWE-1104"])[0] if isinstance(item.get("cwes"), list) else "CWE-1104",
                published_at=str(item.get("dateAdded", "")),
                updated_at=now,
            )
            if self.upsert(entry):
                added += 1
        return added

    def sync_osv_for_packages(
        self, eco_packages: list[tuple[str, str, str]], max_details: int = 20
    ) -> int:
        """Query OSV.dev for exact project dependencies and persist fixed versions + mitigations."""
        eco_map = {"npm": "npm", "maven": "Maven", "composer": "Packagist", "pypi": "PyPI"}
        queries: list[dict[str, Any]] = []
        refs: list[tuple[str, str, str]] = []

        for eco, pkg, raw_ver in eco_packages:
            osv_eco = eco_map.get(eco.lower())
            parsed = _parse_ver_tuple(raw_ver)
            if not osv_eco or not parsed:
                continue
            ver_str = ".".join(str(x) for x in parsed)
            queries.append({"package": {"name": pkg, "ecosystem": osv_eco}, "version": ver_str})
            refs.append((eco.lower(), pkg, ver_str))

        if not queries:
            return 0

        batch_resp = _http_post_json(OSV_BATCH_URL, {"queries": queries})
        added = 0
        fetched_details = 0
        now = datetime.now(timezone.utc).isoformat()

        for (eco, pkg, ver_str), res in zip(refs, batch_resp.get("results", [])):
            for vuln_stub in res.get("vulns", [])[:3]:
                vid = str(vuln_stub.get("id", "")).strip()
                if not vid:
                    continue

                fixed_versions: list[str] = []
                summary = f"OSV vulnerability {vid} affecting {pkg}@{ver_str}."
                references = [f"https://osv.dev/vulnerability/{vid}"]
                severity = "HIGH"

                if fetched_details < max_details:
                    try:
                        detail = _http_get_json(OSV_VULN_URL.format(vuln_id=urllib.parse.quote(vid)))
                        fetched_details += 1
                        summary = str(detail.get("summary") or detail.get("details") or summary)[:400]
                        for aff in detail.get("affected", []):
                            for rng in aff.get("ranges", []):
                                for ev in rng.get("events", []):
                                    if "fixed" in ev:
                                        fixed_versions.append(str(ev["fixed"]))
                        for ref_obj in detail.get("references", [])[:3]:
                            url = ref_obj.get("url")
                            if url:
                                references.append(str(url))
                        db_sev = str(detail.get("database_specific", {}).get("severity", "")).upper()
                        if db_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                            severity = db_sev
                    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                        pass

                fixed_str = ", ".join(sorted(set(fixed_versions))[:3])
                mitigation = (
                    f"Upgrade {pkg} to fixed version ({fixed_str}) and regenerate lockfiles."
                    if fixed_str
                    else f"Review advisory {vid} and upgrade {pkg} to the latest patched release."
                )

                entry = CVEEntry(
                    cve_id=vid,
                    source="osv",
                    ecosystem=eco,
                    package=pkg,
                    severity=severity,
                    title=f"{vid} in {pkg}",
                    summary=summary,
                    mitigation=mitigation,
                    fixed_versions=sorted(set(fixed_versions)),
                    references=references,
                    updated_at=now,
                )
                if self.upsert(entry):
                    added += 1
        return added

    def sync_nvd_recent(self, keywords: list[str], days_back: int = 14) -> int:
        """Query NVD CVE 2.0 API for recent CRITICAL/HIGH CVEs affecting native engines & stacks."""
        added = 0
        now_dt = datetime.now(timezone.utc)
        start_dt = now_dt - timedelta(days=days_back)
        headers: dict[str, str] = {}
        nvd_key = os.getenv("NVD_API_KEY", "").strip()
        if nvd_key:
            headers["apiKey"] = nvd_key

        for kw in keywords[:6]:
            params = urllib.parse.urlencode(
                {
                    "keywordSearch": kw,
                    "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": now_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": 10,
                }
            )
            data = _http_get_json(f"{NVD_API_URL}?{params}", headers=headers, timeout=12)
            for item in data.get("vulnerabilities", []):
                cve_obj = item.get("cve", {})
                cve_id = str(cve_obj.get("id", "")).strip()
                if not cve_id:
                    continue
                descs = cve_obj.get("descriptions", [])
                desc_en = next(
                    (d.get("value", "") for d in descs if d.get("lang") == "en"), ""
                )
                severity = "HIGH"
                metrics = cve_obj.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        sev_val = str(
                            metrics[key][0].get("cvssData", {}).get("baseSeverity", "HIGH")
                        ).upper()
                        if sev_val in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                            severity = sev_val
                        break
                refs = [
                    str(r.get("url"))
                    for r in cve_obj.get("references", [])[:3]
                    if r.get("url")
                ]
                entry = CVEEntry(
                    cve_id=cve_id,
                    source="nvd",
                    ecosystem="c_cpp" if kw.lower() in ("openssl", "glibc", "linux", "php", "nginx") else "generic",
                    package=kw.lower(),
                    severity=severity,
                    title=f"{cve_id} ({kw})",
                    summary=desc_en[:400],
                    mitigation=f"Apply vendor patch for {kw} referenced in {cve_id} and verify minimum patched version in lockfile/base image.",
                    references=refs or [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                    published_at=str(cve_obj.get("published", "")),
                    updated_at=now_dt.isoformat(),
                )
                if self.upsert(entry):
                    added += 1
        return added

    def sync_all(
        self,
        eco_packages: list[tuple[str, str, str]] | None = None,
        nvd_keywords: list[str] | None = None,
        include_nvd: bool = False,
    ) -> SyncStats:
        """Auto-refresh local CVE KB from CISA KEV + OSV.dev (+ optional NVD) and persist to disk."""
        stats = SyncStats(synced_at=datetime.now(timezone.utc).isoformat())

        try:
            stats.cisa_kev_added = self.sync_cisa_kev()
        except Exception as exc:  # noqa: BLE001
            stats.errors.append(f"CISA KEV sync skipped: {type(exc).__name__}")

        if eco_packages:
            try:
                stats.osv_added = self.sync_osv_for_packages(eco_packages)
            except Exception as exc:  # noqa: BLE001
                stats.errors.append(f"OSV.dev sync skipped: {type(exc).__name__}")

        if include_nvd and nvd_keywords:
            try:
                stats.nvd_added = self.sync_nvd_recent(nvd_keywords)
            except Exception as exc:  # noqa: BLE001
                stats.errors.append(f"NVD sync skipped: {type(exc).__name__}")

        self.last_synced_at = stats.synced_at
        stats.total_entries = len(self.entries)
        self.save()
        return stats

    def search(self, query: str, ecosystem: str | None = None, limit: int = 8) -> list[CVEEntry]:
        """Search local CVE Knowledge Base by exact CVE/GHSA ID, package, technology, or keyword."""
        raw_q = query.strip()
        if not raw_q:
            return []

        # Exact CVE / GHSA / OSV identifier lookup takes priority
        if re.fullmatch(r"(?:CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|OSV-[A-Za-z0-9-]+)", raw_q, re.IGNORECASE):
            exact = [
                e for e in self.entries.values() if e.cve_id.lower() == raw_q.lower()
            ]
            if exact:
                return exact[:limit]

        tokens = [
            t.lower()
            for t in re.split(r"[\s,:/]+", raw_q)
            if len(t) >= 2 and t.lower() not in {"cve", "the", "and", "for"}
        ]
        if not tokens:
            return []

        scored: list[tuple[int, CVEEntry]] = []
        for entry in self.entries.values():
            if ecosystem and entry.ecosystem not in (ecosystem.lower(), "generic"):
                continue
            haystack = (
                f"{entry.cve_id} {entry.package} {entry.title} {entry.summary} {entry.mitigation}"
            ).lower()
            score = sum(
                3 if t in entry.package.lower() or t in entry.cve_id.lower() else 1
                for t in tokens
                if t in haystack
            )
            if score > 0:
                if entry.actively_exploited:
                    score += 2
                scored.append((score, entry))

        scored.sort(
            key=lambda pair: (-pair[0], -Severity.from_str(pair[1].severity).rank, pair[1].cve_id)
        )
        return [entry for _, entry in scored[:limit]]

    def match_package(self, ecosystem: str, package: str, raw_version: str) -> list[CVEEntry]:
        """Check local KB entries matching a package and version below its fixed version."""
        parsed = _parse_ver_tuple(raw_version)
        matches: list[CVEEntry] = []
        pkg_lower = package.lower()
        eco_lower = ecosystem.lower()

        for entry in self.entries.values():
            if entry.package.lower() != pkg_lower:
                continue
            if entry.ecosystem.lower() not in (eco_lower, "generic"):
                continue
            if parsed and entry.fixed_versions:
                fixed_tuples = [t for v in entry.fixed_versions if (t := _parse_ver_tuple(v))]
                if fixed_tuples and all(parsed >= ft for ft in fixed_tuples):
                    continue
            matches.append(entry)
        return matches
