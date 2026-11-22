"""Open-source dependency & supply-chain (SCA) scanner across npm, Maven, Composer, and Python."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aiops_auditor.models import Finding, Severity

if TYPE_CHECKING:
    from aiops_auditor.intel.cve_kb import CVEKnowledgeBase


@dataclass(frozen=True)
class KnownAdvisory:
    ecosystem: str  # npm | maven | composer | pypi
    package: str
    cve: str
    vuln_family: str
    severity: Severity
    fixed_version: tuple[int, ...]
    title: str
    description: str


# Curated high-impact open-source RCE / deserialization / supply-chain advisories
KNOWN_ADVISORIES: list[KnownAdvisory] = [
    KnownAdvisory(
        ecosystem="npm",
        package="react-server-dom-webpack",
        cve="CVE-2025-55182",
        vuln_family="node2shell",
        severity=Severity.CRITICAL,
        fixed_version=(19, 0, 1),
        title="React Server Components Flight Protocol Unsafe Deserialization (React2Shell / node2shell)",
        description=(
            "Vulnerable versions of react-server-dom-* mishandle Flight protocol deserialization, "
            "allowing unauthenticated remote code execution on RSC servers."
        ),
    ),
    KnownAdvisory(
        ecosystem="npm",
        package="react-server-dom-turbopack",
        cve="CVE-2025-55182",
        vuln_family="node2shell",
        severity=Severity.CRITICAL,
        fixed_version=(19, 0, 1),
        title="React Server Components Turbopack Unsafe Deserialization (React2Shell / node2shell)",
        description="Vulnerable react-server-dom-turbopack Flight protocol deserialization risk.",
    ),
    KnownAdvisory(
        ecosystem="npm",
        package="next",
        cve="CVE-2025-29927",
        vuln_family="node2shell",
        severity=Severity.CRITICAL,
        fixed_version=(15, 2, 3),
        title="Next.js Middleware Authorization Bypass & RSC Deserialization Exposure",
        description=(
            "Older Next.js 15.x releases are affected by middleware bypass (CVE-2025-29927) "
            "and bundled RSC vulnerabilities."
        ),
    ),
    KnownAdvisory(
        ecosystem="npm",
        package="lodash",
        cve="CVE-2020-8203",
        vuln_family="node2shell",
        severity=Severity.HIGH,
        fixed_version=(4, 17, 21),
        title="Lodash Prototype Pollution Vulnerability",
        description="Lodash < 4.17.21 allows prototype pollution which is frequently chained into Node.js RCE gadgets.",
    ),
    KnownAdvisory(
        ecosystem="npm",
        package="serialize-javascript",
        cve="CVE-2020-7660",
        vuln_family="node2shell",
        severity=Severity.HIGH,
        fixed_version=(3, 1, 0),
        title="serialize-javascript Unsafe Serialization / Code Injection",
        description="serialize-javascript < 3.1.0 mishandles RegExp/Date serialization leading to code injection.",
    ),
    KnownAdvisory(
        ecosystem="maven",
        package="org.apache.logging.log4j:log4j-core",
        cve="CVE-2021-44228",
        vuln_family="java4shell",
        severity=Severity.CRITICAL,
        fixed_version=(2, 17, 1),
        title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell / java4shell)",
        description="log4j-core < 2.17.1 allows JNDI lookup injection via untrusted log messages leading to RCE.",
    ),
    KnownAdvisory(
        ecosystem="maven",
        package="org.springframework:spring-beans",
        cve="CVE-2022-22965",
        vuln_family="java4shell",
        severity=Severity.CRITICAL,
        fixed_version=(5, 3, 18),
        title="Spring Framework ClassLoader Manipulation RCE (Spring4Shell / java4shell)",
        description="spring-beans < 5.3.18 is vulnerable to ClassLoader property binding RCE on JDK 9+.",
    ),
    KnownAdvisory(
        ecosystem="composer",
        package="phpunit/phpunit",
        cve="CVE-2017-9841",
        vuln_family="php2shell",
        severity=Severity.CRITICAL,
        fixed_version=(5, 6, 3),
        title="PHPUnit eval-stdin.php Remote Code Execution",
        description="Legacy PHPUnit versions expose eval-stdin.php if web-accessible.",
    ),
    KnownAdvisory(
        ecosystem="composer",
        package="laravel/framework",
        cve="CVE-2021-3129",
        vuln_family="php2shell",
        severity=Severity.CRITICAL,
        fixed_version=(8, 4, 3),
        title="Laravel Framework / Ignition Deserialization & File Write RCE",
        description="Outdated Laravel releases expose gadget chains and debug RCE primitives.",
    ),
    KnownAdvisory(
        ecosystem="pypi",
        package="pyyaml",
        cve="CVE-2020-14343",
        vuln_family="python-deser",
        severity=Severity.CRITICAL,
        fixed_version=(5, 4, 0),
        title="PyYAML Arbitrary Code Execution via FullLoader",
        description="PyYAML < 5.4 allows arbitrary code execution when loading untrusted YAML documents.",
    ),
]

SUSPICIOUS_NPM_SCRIPT_RE = re.compile(
    r"(curl\s+.*\|\s*(?:sh|bash)|wget\s+.*\|\s*(?:sh|bash)|powershell\s+-e|eval\s*\(|nc\s+-e|/dev/tcp/)",
    re.IGNORECASE,
)


def _parse_version(raw_ver: str) -> tuple[int, ...] | None:
    cleaned = re.sub(r"^[^0-9]*", "", raw_ver.strip())
    match = re.match(r"(\d+(?:\.\d+)*)", cleaned)
    if not match:
        return None
    parts = [int(p) for p in match.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _check_advisories(
    ecosystem: str,
    packages: dict[str, str],
    rel_path: str,
    enable_osv_lookup: bool = False,
    cve_kb: "CVEKnowledgeBase | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_cves: set[tuple[str, str]] = set()
    advisory_map = {
        adv.package.lower(): adv for adv in KNOWN_ADVISORIES if adv.ecosystem == ecosystem
    }

    for pkg_name, raw_ver in packages.items():
        adv = advisory_map.get(pkg_name.lower())
        parsed_ver = _parse_version(raw_ver)
        if adv and parsed_ver and parsed_ver < adv.fixed_version:
            fixed_str = ".".join(str(x) for x in adv.fixed_version)
            seen_cves.add((pkg_name.lower(), adv.cve.upper()))
            findings.append(
                Finding(
                    rule_id=f"SCA-{ecosystem.upper()}-{adv.cve}",
                    title=f"{adv.title} ({pkg_name}@{raw_ver})",
                    category="SCA",
                    ecosystem=ecosystem,
                    vuln_family=adv.vuln_family,
                    severity=adv.severity,
                    file_path=rel_path,
                    line=1,
                    cwe="CWE-1104",
                    cve=adv.cve,
                    description=adv.description,
                    snippet=f'"{pkg_name}": "{raw_ver}"',
                    remediation=f"Upgrade {pkg_name} to >= {fixed_str} and regenerate lockfiles.",
                )
            )

        # Match against live-synced local CVE Knowledge Base (CISA KEV / OSV / NVD)
        if cve_kb is not None:
            for kb_entry in cve_kb.match_package(ecosystem, pkg_name, raw_ver):
                key = (pkg_name.lower(), kb_entry.cve_id.upper())
                if key in seen_cves:
                    continue
                seen_cves.add(key)
                kev_suffix = " [CISA KEV]" if kb_entry.actively_exploited else ""
                findings.append(
                    Finding(
                        rule_id=f"SCA-KB-{kb_entry.cve_id}",
                        title=f"{kb_entry.title}{kev_suffix} ({pkg_name}@{raw_ver})",
                        category="SCA",
                        ecosystem=ecosystem,
                        vuln_family="live-cve-kb",
                        severity=Severity.from_str(kb_entry.severity),
                        file_path=rel_path,
                        line=1,
                        cwe=kb_entry.cwe,
                        cve=kb_entry.cve_id,
                        description=kb_entry.summary,
                        snippet=f'"{pkg_name}": "{raw_ver}"',
                        remediation=kb_entry.mitigation,
                    )
                )

    if enable_osv_lookup and packages:
        findings.extend(_query_osv_batch(ecosystem, packages, rel_path))

    return findings


def _query_osv_batch(
    ecosystem: str, packages: dict[str, str], rel_path: str
) -> list[Finding]:
    """Optional live OSV.dev vulnerability query for up-to-date open-source CVEs."""
    eco_map = {"npm": "npm", "maven": "Maven", "composer": "Packagist", "pypi": "PyPI"}
    osv_eco = eco_map.get(ecosystem)
    if not osv_eco:
        return []

    queries: list[dict[str, Any]] = []
    pkg_list: list[tuple[str, str]] = []
    for name, raw_ver in packages.items():
        parsed = _parse_version(raw_ver)
        if not parsed:
            continue
        ver_str = ".".join(str(x) for x in parsed)
        queries.append({"package": {"name": name, "ecosystem": osv_eco}, "version": ver_str})
        pkg_list.append((name, ver_str))

    if not queries:
        return []

    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    for (pkg_name, ver_str), result in zip(pkg_list, payload.get("results", [])):
        for vuln in result.get("vulns", [])[:3]:
            vid = vuln.get("id", "OSV-UNKNOWN")
            findings.append(
                Finding(
                    rule_id=f"SCA-OSV-{vid}",
                    title=f"OSV Advisory {vid} in {pkg_name}@{ver_str}",
                    category="SCA",
                    ecosystem=ecosystem,
                    vuln_family="oss-dependency",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=1,
                    cwe="CWE-1104",
                    cve=vid,
                    description=vuln.get("summary", f"Open-source advisory {vid} affects {pkg_name}@{ver_str}."),
                    snippet=f"{pkg_name}=={ver_str}",
                    remediation=f"Review https://osv.dev/vulnerability/{vid} and upgrade {pkg_name}.",
                )
            )
    return findings


def _scan_package_json(
    rel_path: str,
    content: str,
    enable_osv: bool,
    cve_kb: "CVEKnowledgeBase | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings

    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        sec_val = data.get(section)
        if isinstance(sec_val, dict):
            for k, v in sec_val.items():
                if isinstance(v, str):
                    deps[k] = v

    findings.extend(
        _check_advisories("npm", deps, rel_path, enable_osv_lookup=enable_osv, cve_kb=cve_kb)
    )

    # Supply-chain check: malicious/risky npm lifecycle hooks
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            cmd = scripts.get(hook)
            if isinstance(cmd, str) and SUSPICIOUS_NPM_SCRIPT_RE.search(cmd):
                findings.append(
                    Finding(
                        rule_id="SCA-NPM-SUPPLYCHAIN-001",
                        title=f"Suspicious npm '{hook}' lifecycle script (supply-chain RCE risk)",
                        category="SCA",
                        ecosystem="nodejs",
                        vuln_family="supply-chain",
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line=1,
                        cwe="CWE-829",
                        description=(
                            f"Lifecycle script '{hook}' executes a remote pipe-to-shell or obfuscated "
                            "command during package installation."
                        ),
                        snippet=f'"{hook}": "{cmd}"',
                        remediation="Remove remote curl/wget pipe-to-shell hooks and run `npm ci --ignore-scripts` in CI.",
                    )
                )
    return findings


def _scan_composer_json(
    rel_path: str,
    content: str,
    enable_osv: bool,
    cve_kb: "CVEKnowledgeBase | None" = None,
) -> list[Finding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps: dict[str, str] = {}
    for section in ("require", "require-dev"):
        sec_val = data.get(section)
        if isinstance(sec_val, dict):
            for k, v in sec_val.items():
                if isinstance(v, str):
                    deps[k] = v
    return _check_advisories(
        "composer", deps, rel_path, enable_osv_lookup=enable_osv, cve_kb=cve_kb
    )


def _scan_pom_xml(
    rel_path: str,
    content: str,
    enable_osv: bool,
    cve_kb: "CVEKnowledgeBase | None" = None,
) -> list[Finding]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    deps: dict[str, str] = {}
    for elem in root.iter():
        if elem.tag.endswith("dependency"):
            gid = aid = ver = ""
            for child in elem:
                tag = child.tag.split("}")[-1]
                text = (child.text or "").strip()
                if tag == "groupId":
                    gid = text
                elif tag == "artifactId":
                    aid = text
                elif tag == "version":
                    ver = text
            if gid and aid and ver:
                deps[f"{gid}:{aid}"] = ver

    return _check_advisories(
        "maven", deps, rel_path, enable_osv_lookup=enable_osv, cve_kb=cve_kb
    )


def _scan_requirements_txt(
    rel_path: str,
    content: str,
    enable_osv: bool,
    cve_kb: "CVEKnowledgeBase | None" = None,
) -> list[Finding]:
    deps: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=)\s*([0-9][^\s;#]*)", stripped)
        if match:
            deps[match.group(1).lower()] = match.group(2)
    return _check_advisories(
        "pypi", deps, rel_path, enable_osv_lookup=enable_osv, cve_kb=cve_kb
    )


def extract_manifest_packages(file_path: Path, content: str) -> list[tuple[str, str, str]]:
    """Extract (ecosystem, package, version) triples for live CVE KB syncing."""
    name = file_path.name.lower()
    extracted: list[tuple[str, str, str]] = []

    if name == "package.json":
        try:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                sec_val = data.get(section)
                if isinstance(sec_val, dict):
                    for k, v in sec_val.items():
                        if isinstance(v, str):
                            extracted.append(("npm", k, v))
        except json.JSONDecodeError:
            pass
    elif name == "composer.json":
        try:
            data = json.loads(content)
            for section in ("require", "require-dev"):
                sec_val = data.get(section)
                if isinstance(sec_val, dict):
                    for k, v in sec_val.items():
                        if isinstance(v, str):
                            extracted.append(("composer", k, v))
        except json.JSONDecodeError:
            pass
    elif name == "pom.xml":
        try:
            root = ET.fromstring(content)
            for elem in root.iter():
                if elem.tag.endswith("dependency"):
                    gid = aid = ver = ""
                    for child in elem:
                        tag = child.tag.split("}")[-1]
                        text = (child.text or "").strip()
                        if tag == "groupId":
                            gid = text
                        elif tag == "artifactId":
                            aid = text
                        elif tag == "version":
                            ver = text
                    if gid and aid and ver:
                        extracted.append(("maven", f"{gid}:{aid}", ver))
        except ET.ParseError:
            pass
    elif name.startswith("requirements") and name.endswith(".txt"):
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=)\s*([0-9][^\s;#]*)", stripped)
            if match:
                extracted.append(("pypi", match.group(1).lower(), match.group(2)))

    return extracted


def scan_dependency_manifest(
    file_path: Path,
    rel_path: str,
    content: str,
    enable_osv_lookup: bool = False,
    cve_kb: "CVEKnowledgeBase | None" = None,
) -> list[Finding]:
    """Audit open-source dependency manifests for known critical CVEs & supply-chain risks."""
    name = file_path.name.lower()
    if name == "package.json":
        return _scan_package_json(rel_path, content, enable_osv_lookup, cve_kb=cve_kb)
    if name == "composer.json":
        return _scan_composer_json(rel_path, content, enable_osv_lookup, cve_kb=cve_kb)
    if name == "pom.xml":
        return _scan_pom_xml(rel_path, content, enable_osv_lookup, cve_kb=cve_kb)
    if name.startswith("requirements") and name.endswith(".txt"):
        return _scan_requirements_txt(rel_path, content, enable_osv_lookup, cve_kb=cve_kb)
    return []

