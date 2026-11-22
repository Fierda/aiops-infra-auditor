"""Low-level native engine & memory-safety scanner (C, C++, Assembly, Rust FFI, Build Hardening)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aiops_auditor.models import Finding, Severity


@dataclass(frozen=True)
class NativeRule:
    rule_id: str
    title: str
    ecosystem: str
    vuln_family: str
    severity: Severity
    cwe: str
    pattern: re.Pattern[str]
    description: str
    remediation: str
    negative_pattern: re.Pattern[str] | None = None


C_CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
ASM_EXTENSIONS = {".s", ".asm"}
BUILD_FILENAMES = {"makefile", "cmakelists.txt", "binding.gyp", "meson.build"}

C_CPP_RULES: list[NativeRule] = [
    NativeRule(
        rule_id="NAT-C-001",
        title="Unbounded C/C++ buffer operation (stack/heap buffer overflow risk)",
        ecosystem="c_cpp",
        vuln_family="memory-corruption",
        severity=Severity.CRITICAL,
        cwe="CWE-120",
        pattern=re.compile(
            r"\b(?:gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat)\s*\("
            r"|\bscanf\s*\(\s*\"[^\"]*%s"
        ),
        description=(
            "Unbounded C/C++ string/buffer functions do not enforce destination capacity, "
            "allowing memory corruption and code execution in native engines or extensions."
        ),
        remediation=(
            "Replace with bounded equivalents (snprintf, strlcpy/strncpy with explicit null-termination, "
            "fgets, or std::string/std::span in C++)."
        ),
    ),
    NativeRule(
        rule_id="NAT-C-002",
        title="Potential C/C++ format string vulnerability",
        ecosystem="c_cpp",
        vuln_family="memory-corruption",
        severity=Severity.CRITICAL,
        cwe="CWE-134",
        pattern=re.compile(
            r"\b(?:printf|vprintf)\s*\(\s*[A-Za-z_][A-Za-z0-9_>.\[\]-]*\s*\)"
            r"|\b(?:fprintf|syslog)\s*\([^,]+,\s*[A-Za-z_][A-Za-z0-9_>.\[\]-]*\s*\)"
        ),
        description=(
            "Passing a non-literal variable directly as the format string allows arbitrary stack/memory "
            "reads and writes via format specifiers."
        ),
        remediation='Always pass a constant literal format string, e.g., printf("%s", user_msg).',
    ),
    NativeRule(
        rule_id="NAT-C-003",
        title="Native C/C++ OS command execution sink (system/popen/exec)",
        ecosystem="c_cpp",
        vuln_family="native-cmdi",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        pattern=re.compile(r"\b(?:system|popen)\s*\(\s*[^\"')]"),
        description=(
            "Calling system() or popen() with a dynamic buffer invokes /bin/sh and enables "
            "command injection inside native extensions or services."
        ),
        remediation="Avoid system()/popen(); use posix_spawn() or execve() with fixed argument vectors.",
    ),
    NativeRule(
        rule_id="NAT-C-004",
        title="Unchecked integer multiplication in heap allocation (integer overflow -> heap overflow)",
        ecosystem="c_cpp",
        vuln_family="memory-corruption",
        severity=Severity.HIGH,
        cwe="CWE-190",
        pattern=re.compile(r"\b(?:malloc|realloc)\s*\([^;)]*\*[^;)]*\)"),
        negative_pattern=re.compile(r"__builtin_mul_overflow|SIZE_MAX|calloc"),
        description=(
            "Multiplying untrusted counts inside malloc()/realloc() without overflow checking can wrap "
            "around to a tiny allocation, causing a subsequent heap buffer overflow."
        ),
        remediation=(
            "Use calloc(count, elem_size) or check bounds with __builtin_mul_overflow() before allocation."
        ),
    ),
    NativeRule(
        rule_id="NAT-C-005",
        title="Unsafe raw memory copy or unbounded stack allocation (memcpy/alloca)",
        ecosystem="c_cpp",
        vuln_family="memory-corruption",
        severity=Severity.HIGH,
        cwe="CWE-787",
        pattern=re.compile(r"\balloca\s*\(|\bmemcpy\s*\([^,]+,[^,]+,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"),
        negative_pattern=re.compile(r"sizeof\s*\(|min\s*\(|<="),
        description=(
            "alloca() with dynamic sizes risks stack exhaustion/clash, and memcpy() with unvalidated "
            "length variables risks out-of-bounds memory writes."
        ),
        remediation="Validate length against destination buffer capacity before memcpy() and avoid alloca().",
    ),
    NativeRule(
        rule_id="NAT-ASM-001",
        title="Inline assembly block inside native C/C++ source",
        ecosystem="assembly",
        vuln_family="lowlevel-asm",
        severity=Severity.HIGH,
        cwe="CWE-676",
        pattern=re.compile(r"\b(?:__asm__|__asm|asm)\s*(?:volatile)?\s*\("),
        description=(
            "Inline assembly bypasses compiler memory-safety checks, stack protection, and type safety; "
            "requires strict review for clobber lists, ABI compliance, and side channels."
        ),
        remediation=(
            "Replace inline assembly with standard C/C++ intrinsics or audited crypto/SIMD libraries; "
            "if required, document register clobbers and enable sanitizer verification."
        ),
    ),
]

ASM_RULES: list[NativeRule] = [
    NativeRule(
        rule_id="NAT-ASM-002",
        title="Assembly source marks stack executable (.note.GNU-stack 'x')",
        ecosystem="assembly",
        vuln_family="lowlevel-asm",
        severity=Severity.CRITICAL,
        cwe="CWE-119",
        pattern=re.compile(r'\.section\s+\.note\.GNU-stack\s*,\s*"[^"]*x[^"]*"', re.IGNORECASE),
        description=(
            "Marking .note.GNU-stack executable disables NX/DEP across the entire linked binary "
            "or language runtime module."
        ),
        remediation='Mark the stack non-executable: .section .note.GNU-stack,"",@progbits',
    ),
    NativeRule(
        rule_id="NAT-ASM-003",
        title="Direct raw syscall / software interrupt in assembly module",
        ecosystem="assembly",
        vuln_family="lowlevel-asm",
        severity=Severity.HIGH,
        cwe="CWE-676",
        pattern=re.compile(r"^\s*(?:syscall|sysenter|int\s+0x80|svc\s+#?0)\b", re.IGNORECASE),
        description=(
            "Direct syscalls bypass libc wrappers, seccomp audit helpers, and runtime security checks; "
            "verify strict legitimacy before deployment."
        ),
        remediation="Use standard audited libc/OS APIs instead of direct assembly syscalls.",
    ),
]

BUILD_HARDENING_RULES: list[NativeRule] = [
    NativeRule(
        rule_id="NAT-BUILD-001",
        title="Native build disables stack canary or enables executable stack",
        ecosystem="build_hardening",
        vuln_family="compiler-hardening",
        severity=Severity.CRITICAL,
        cwe="CWE-119",
        pattern=re.compile(r"-fno-stack-protector|-z[\s,]+execstack|--no-nxcompat"),
        description=(
            "Disabling stack protectors (-fno-stack-protector) or enabling executable stacks (-z execstack) "
            "removes critical exploit mitigations from C/C++ binaries and native extensions."
        ),
        remediation=(
            "Enable full hardening flags: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie "
            "-Wl,-z,relro,-z,now,-z,noexecstack."
        ),
    ),
    NativeRule(
        rule_id="NAT-BUILD-002",
        title="Native build weakens binary mitigations (PIE/RELRO/FORTIFY disabled)",
        ecosystem="build_hardening",
        vuln_family="compiler-hardening",
        severity=Severity.HIGH,
        cwe="CWE-693",
        pattern=re.compile(r"-no-pie|-fno-pie|-D_FORTIFY_SOURCE=0|-Wl,-z,norelro"),
        description="Weakened linker/compiler hardening flags reduce ASLR and GOT/PLT memory protections.",
        remediation="Compile with -fPIE -pie -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now.",
    ),
]

RUST_UNSAFE_RE = re.compile(
    r"\bunsafe\s*\{|\bstd::mem::transmute\b|\bfrom_raw_parts(?:_mut)?\b"
)

EOL_RUNTIME_RE = re.compile(
    r"^FROM\s+(?P<img_ref>(?:php:(?:5|7|8\.0)|node:(?:12|14|16|18)|python:(?:2|3\.[678])|openjdk:(?:8|11))\S*)",
    re.IGNORECASE,
)


def _snippet(lines: list[str], line_no: int, radius: int = 3) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))


def _scan_uaf_heuristic(rel_path: str, lines: list[str]) -> list[Finding]:
    """Detect free(ptr) followed by reuse or double-free without ptr = NULL in the same function."""
    findings: list[Finding] = []
    free_re = re.compile(r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;")

    for idx, line in enumerate(lines, start=1):
        match = free_re.search(line)
        if not match:
            continue
        var = match.group(1)
        lookahead = lines[idx : min(len(lines), idx + 12)]
        nullified = False
        for offset, next_line in enumerate(lookahead, start=1):
            stripped = next_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if stripped == "}":
                break
            if re.search(rf"\b{re.escape(var)}\s*=\s*(?:NULL|nullptr|0)\b", stripped):
                nullified = True
                break
            if re.search(rf"\b{re.escape(var)}\b", stripped) and not nullified:
                findings.append(
                    Finding(
                        rule_id="NAT-C-006",
                        title=f"Potential Use-After-Free / Double-Free on pointer '{var}'",
                        category="SAST",
                        ecosystem="c_cpp",
                        vuln_family="memory-corruption",
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line=idx + offset,
                        cwe="CWE-416",
                        description=(
                            f"Pointer '{var}' is referenced after free({var}) at line {idx} "
                            "without being reassigned or nullified."
                        ),
                        snippet=_snippet(lines, idx + offset, radius=4),
                        remediation=f"Set `{var} = NULL;` immediately after `free({var});` and do not dereference freed memory.",
                    )
                )
                break
    return findings


def scan_native_lowlevel(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    """Audit C/C++, Assembly, Rust unsafe FFI, native build hardening, and EOL runtime engines."""
    findings: list[Finding] = []
    suffix = file_path.suffix.lower()
    name_lower = file_path.name.lower()
    lines = content.splitlines()

    # 1. C / C++ native source & headers
    if suffix in C_CPP_EXTENSIONS:
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            window = "\n".join(lines[max(0, idx - 5) : min(len(lines), idx + 5)])
            for rule in C_CPP_RULES:
                if not rule.pattern.search(line):
                    continue
                if rule.negative_pattern and rule.negative_pattern.search(window):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category="SAST",
                        ecosystem=rule.ecosystem,
                        vuln_family=rule.vuln_family,
                        severity=rule.severity,
                        file_path=rel_path,
                        line=idx,
                        cwe=rule.cwe,
                        description=rule.description,
                        snippet=_snippet(lines, idx),
                        remediation=rule.remediation,
                    )
                )
        findings.extend(_scan_uaf_heuristic(rel_path, lines))
        return findings

    # 2. Standalone Assembly source (.s, .S, .asm)
    if suffix in ASM_EXTENSIONS:
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(";") or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule in ASM_RULES:
                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            category="SAST",
                            ecosystem=rule.ecosystem,
                            vuln_family=rule.vuln_family,
                            severity=rule.severity,
                            file_path=rel_path,
                            line=idx,
                            cwe=rule.cwe,
                            description=rule.description,
                            snippet=_snippet(lines, idx),
                            remediation=rule.remediation,
                        )
                    )
        return findings

    # 3. Rust native FFI unsafe blocks
    if suffix == ".rs":
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if RUST_UNSAFE_RE.search(line):
                findings.append(
                    Finding(
                        rule_id="NAT-FFI-001",
                        title="Rust unsafe memory/FFI operation requires audit",
                        category="SAST",
                        ecosystem="rust_ffi",
                        vuln_family="memory-corruption",
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=idx,
                        cwe="CWE-119",
                        description="Rust unsafe blocks bypass borrow-checker memory guarantees at FFI/pointer boundaries.",
                        snippet=_snippet(lines, idx),
                        remediation="Minimize unsafe scope, validate pointer/slice invariants, and add Miri/ASan tests.",
                    )
                )
        return findings

    # 4. Native build scripts / compiler hardening flags
    if (
        name_lower in BUILD_FILENAMES
        or name_lower.endswith(".makefile")
        or name_lower.endswith(".mk")
        or suffix == ".cmake"
    ):
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for rule in BUILD_HARDENING_RULES:
                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            category="IAC",
                            ecosystem=rule.ecosystem,
                            vuln_family=rule.vuln_family,
                            severity=rule.severity,
                            file_path=rel_path,
                            line=idx,
                            cwe=rule.cwe,
                            description=rule.description,
                            snippet=_snippet(lines, idx),
                            remediation=rule.remediation,
                        )
                    )
        return findings

    # 5. EOL Language Runtime / Native Engine base images in Dockerfiles
    if name_lower == "dockerfile" or name_lower.startswith("dockerfile."):
        for idx, line in enumerate(lines, start=1):
            m = EOL_RUNTIME_RE.match(line.strip())
            if m:
                findings.append(
                    Finding(
                        rule_id="NAT-ENGINE-001",
                        title=f"EOL language runtime/C-engine base image ({m.group('img_ref')})",
                        category="SCA",
                        ecosystem="native_engine",
                        vuln_family="runtime-engine",
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=idx,
                        cwe="CWE-1104",
                        description=(
                            f"Base image '{m.group('img_ref')}' ships an end-of-life C/C++ runtime engine "
                            "(Zend/V8/CPython/JVM/OpenSSL) that no longer receives memory-safety security patches."
                        ),
                        snippet=_snippet(lines, idx),
                        remediation="Upgrade to a currently supported LTS runtime image (e.g., php:8.3, node:22, python:3.12, eclipse-temurin:21).",
                    )
                )
        return findings

    return findings

