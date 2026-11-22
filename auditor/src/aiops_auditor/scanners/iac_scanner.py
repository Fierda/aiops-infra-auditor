"""Infrastructure-as-Code (Terraform, Ansible, Dockerfile, Compose) security scanner."""

from __future__ import annotations

import re
from pathlib import Path

from aiops_auditor.models import Finding, Severity


def _snippet(lines: list[str], line_no: int, radius: int = 3) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))


def _scan_terraform(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    # Track whether we are inside an ingress block (not egress or route table)
    in_ingress = False
    ingress_brace_depth = 0
    ingress_ports: list[int] = []

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        if re.match(r"^ingress\s*\{", stripped):
            in_ingress = True
            ingress_brace_depth = stripped.count("{") - stripped.count("}")
            ingress_ports = []
        elif in_ingress:
            ingress_brace_depth += stripped.count("{") - stripped.count("}")
            port_m = re.search(r"(?:from_port|to_port)\s*=\s*(\d+)", stripped)
            if port_m:
                ingress_ports.append(int(port_m.group(1)))
            if "0.0.0.0/0" in stripped:
                sensitive_ports = {22, 3389, 3306, 5432, 6379, 27017, 0}
                if not ingress_ports or any(p in sensitive_ports for p in ingress_ports):
                    findings.append(
                        Finding(
                            rule_id="IAC-TF-001",
                            title="Terraform Security Group exposes sensitive port to 0.0.0.0/0",
                            category="IAC",
                            ecosystem="terraform",
                            vuln_family="iac-network",
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line=idx,
                            cwe="CWE-284",
                            description="Ingress rule allows unrestricted internet access (0.0.0.0/0) to management/database port.",
                            snippet=_snippet(lines, idx),
                            remediation="Restrict cidr_blocks to trusted VPN/bastion CIDRs or use AWS SSM Session Manager.",
                        )
                    )
            if ingress_brace_depth <= 0:
                in_ingress = False

        if re.search(r"\bencrypted\s*=\s*false\b", stripped, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-TF-002",
                    title="Terraform storage resource has encryption disabled",
                    category="IAC",
                    ecosystem="terraform",
                    vuln_family="iac-crypto",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-311",
                    description="EBS/RDS/storage resource explicitly sets encrypted = false.",
                    snippet=_snippet(lines, idx),
                    remediation="Set encrypted = true and reference a KMS Customer Managed Key (CMK).",
                )
            )

        if re.search(r'http_tokens\s*=\s*"optional"', stripped):
            findings.append(
                Finding(
                    rule_id="IAC-TF-003",
                    title="EC2 instance allows IMDSv1 (SSRF credential theft risk)",
                    category="IAC",
                    ecosystem="terraform",
                    vuln_family="iac-iam",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-918",
                    description="IMDSv1 enables SSRF vulnerabilities in hosted apps to steal IAM role credentials.",
                    snippet=_snippet(lines, idx),
                    remediation='Enforce IMDSv2 by setting http_tokens = "required" and http_put_response_hop_limit = 1.',
                )
            )

        if re.search(r'acl\s*=\s*"public-read(?:-write)?"', stripped):
            findings.append(
                Finding(
                    rule_id="IAC-TF-004",
                    title="S3 bucket configured with public ACL",
                    category="IAC",
                    ecosystem="terraform",
                    vuln_family="iac-storage",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-200",
                    description="Public S3 ACL exposes bucket contents to unauthorized internet access.",
                    snippet=_snippet(lines, idx),
                    remediation="Remove public ACL and attach aws_s3_bucket_public_access_block with all flags true.",
                )
            )

    return findings


def _scan_ansible(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    checks = [
        (
            "IAC-ANS-001",
            "Ansible executes remote script via pipe-to-shell (curl|sh / wget|bash)",
            Severity.HIGH,
            "CWE-829",
            re.compile(r"(?:curl|wget)\s+[^\n]*\|\s*(?:sh|bash)", re.IGNORECASE),
            "Download verified packages via apt/dnf or verify SHA256 checksums before execution.",
        ),
        (
            "IAC-ANS-002",
            "Ansible weakens SSH hardening (PermitRootLogin yes or PasswordAuthentication yes)",
            Severity.HIGH,
            "CWE-287",
            re.compile(r"\b(?:PermitRootLogin|PasswordAuthentication)\s+yes\b", re.IGNORECASE),
            "Enforce PermitRootLogin no and PasswordAuthentication no per CIS benchmarks.",
        ),
        (
            "IAC-ANS-003",
            "Ansible disables TLS certificate validation (validate_certs: false/no)",
            Severity.HIGH,
            "CWE-295",
            re.compile(r"validate_certs\s*:\s*(?:false|no)\b", re.IGNORECASE),
            "Enable TLS certificate verification (validate_certs: true).",
        ),
        (
            "IAC-ANS-004",
            "Ansible sets world-writable permissions (0777)",
            Severity.MEDIUM,
            "CWE-732",
            re.compile(r'mode\s*:\s*["\']?0?777["\']?'),
            "Use least-privilege file modes such as 0640 or 0750.",
        ),
    ]

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for rule_id, title, sev, cwe, pattern, remed in checks:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        category="IAC",
                        ecosystem="ansible",
                        vuln_family="iac-hardening",
                        severity=sev,
                        file_path=rel_path,
                        line=idx,
                        cwe=cwe,
                        description=title,
                        snippet=_snippet(lines, idx),
                        remediation=remed,
                    )
                )

    return findings


def _scan_dockerfile(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    has_non_root_user = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^FROM\s+\S+:latest(?:\s|$)", stripped, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-DOCKER-001",
                    title="Dockerfile uses unpinned ':latest' base image tag",
                    category="IAC",
                    ecosystem="docker",
                    vuln_family="container-hardening",
                    severity=Severity.MEDIUM,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-829",
                    description="Unpinned ':latest' tags break build reproducibility and supply-chain verification.",
                    snippet=_snippet(lines, idx),
                    remediation="Pin the base image to an explicit version tag or immutable SHA256 digest.",
                )
            )

        user_m = re.match(r"^USER\s+(\S+)", stripped, re.IGNORECASE)
        if user_m:
            u = user_m.group(1).lower()
            if u not in ("root", "0", "0:0"):
                has_non_root_user = True

        if re.search(r"(?:curl|wget)\s+.*\|\s*(?:sh|bash)", stripped, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-DOCKER-002",
                    title="Dockerfile executes unverified remote script via pipe-to-shell",
                    category="IAC",
                    ecosystem="docker",
                    vuln_family="container-hardening",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-829",
                    description="Piping remote scripts directly to sh risks supply-chain compromise.",
                    snippet=_snippet(lines, idx),
                    remediation="Download pinned release artifacts and verify SHA256 checksums before running.",
                )
            )

    if not has_non_root_user:
        findings.append(
            Finding(
                rule_id="IAC-DOCKER-003",
                title="Dockerfile does not switch to a non-root USER",
                category="IAC",
                ecosystem="docker",
                vuln_family="container-hardening",
                severity=Severity.HIGH,
                file_path=rel_path,
                line=1,
                cwe="CWE-250",
                description="Containers running as root expand blast radius on container escape.",
                snippet=lines[0] if lines else "",
                remediation="Create a dedicated system user and add a non-root USER instruction.",
            )
        )

    return findings


def _scan_compose(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        if re.search(r"^\s*privileged\s*:\s*true\b", line, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-COMPOSE-001",
                    title="Docker Compose service runs in privileged mode",
                    category="IAC",
                    ecosystem="docker",
                    vuln_family="container-hardening",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-250",
                    description="privileged: true grants near-host root capabilities to the container.",
                    snippet=_snippet(lines, idx),
                    remediation="Remove privileged: true and grant only minimal Linux capabilities if needed.",
                )
            )
    return findings


def _scan_kubernetes(rel_path: str, content: str) -> list[Finding]:
    """Audit Kubernetes YAML manifests (Deployment, Pod, CronJob, StatefulSet, RBAC)."""
    findings: list[Finding] = []
    lines = content.splitlines()
    is_rbac = bool(re.search(r"^\s*kind\s*:\s*(?:Cluster)?Role\b", content, re.MULTILINE))
    in_host_path = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.search(r"^\s*privileged\s*:\s*true\b", line, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-K8S-001",
                    title="Kubernetes container runs in privileged mode",
                    category="IAC",
                    ecosystem="kubernetes",
                    vuln_family="k8s-hardening",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-250",
                    description="privileged: true gives container full host kernel access and enables node escape.",
                    snippet=_snippet(lines, idx),
                    remediation="Remove privileged: true, drop ALL capabilities, and set allowPrivilegeEscalation: false.",
                )
            )

        if re.search(r"^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b", line, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-K8S-002",
                    title="Kubernetes Pod shares host namespace (hostNetwork/hostPID/hostIPC)",
                    category="IAC",
                    ecosystem="kubernetes",
                    vuln_family="k8s-hardening",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-250",
                    description="Sharing host namespaces weakens Pod isolation and exposes host processes/sockets.",
                    snippet=_snippet(lines, idx),
                    remediation="Remove hostNetwork, hostPID, and hostIPC unless strictly required for CNI/system DaemonSets.",
                )
            )

        if re.search(
            r"^\s*(?:runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false\b)", line, re.IGNORECASE
        ):
            findings.append(
                Finding(
                    rule_id="IAC-K8S-003",
                    title="Kubernetes workload allows execution as root user",
                    category="IAC",
                    ecosystem="kubernetes",
                    vuln_family="k8s-hardening",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-250",
                    description="Running containers as UID 0 violates Pod Security Restricted standards.",
                    snippet=_snippet(lines, idx),
                    remediation="Set securityContext.runAsNonRoot: true and a non-zero runAsUser (e.g., 10001).",
                )
            )

        if re.search(r"^\s*allowPrivilegeEscalation\s*:\s*true\b", line, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-K8S-004",
                    title="Kubernetes container allows privilege escalation",
                    category="IAC",
                    ecosystem="kubernetes",
                    vuln_family="k8s-hardening",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-269",
                    description="allowPrivilegeEscalation: true lets child processes gain higher privileges via setuid binaries.",
                    snippet=_snippet(lines, idx),
                    remediation="Set securityContext.allowPrivilegeEscalation: false.",
                )
            )

        if re.search(r"^\s*hostPath\s*:", line):
            in_host_path = True
        elif in_host_path:
            path_m = re.search(r"^\s*path\s*:\s*['\"]?([^\s'\"]+)", line)
            if path_m:
                hp = path_m.group(1)
                if hp in ("/", "/etc", "/proc", "/var/run/docker.sock", "/run/containerd/containerd.sock"):
                    findings.append(
                        Finding(
                            rule_id="IAC-K8S-005",
                            title=f"Kubernetes Pod mounts sensitive hostPath '{hp}'",
                            category="IAC",
                            ecosystem="kubernetes",
                            vuln_family="k8s-hardening",
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line=idx,
                            cwe="CWE-732",
                            description=f"Mounting hostPath '{hp}' into a container enables host filesystem or runtime takeover.",
                            snippet=_snippet(lines, idx),
                            remediation="Replace sensitive hostPath volumes with emptyDir or a managed PersistentVolumeClaim.",
                        )
                    )
                in_host_path = False

        if is_rbac and re.search(
            r'^\s*(?:verbs|resources)\s*:\s*\[[^\]]*["\']\*["\']|^\s*-\s*["\']\*["\']',
            line,
        ):
            findings.append(
                Finding(
                    rule_id="IAC-K8S-006",
                    title="Overly permissive Kubernetes RBAC wildcard '*' grant",
                    category="IAC",
                    ecosystem="kubernetes",
                    vuln_family="k8s-rbac",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-269",
                    description="Granting wildcard '*' verbs or resources in Role/ClusterRole enables cluster privilege escalation.",
                    snippet=_snippet(lines, idx),
                    remediation="Scope RBAC rules to explicit minimum apiGroups, resources, and verbs.",
                )
            )

        if re.search(r"^\s*image\s*:\s*\S+:latest(?:\s|$)", line, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="IAC-K8S-007",
                    title="Kubernetes container uses unpinned ':latest' image tag",
                    category="IAC",
                    ecosystem="kubernetes",
                    vuln_family="k8s-supply-chain",
                    severity=Severity.MEDIUM,
                    file_path=rel_path,
                    line=idx,
                    cwe="CWE-829",
                    description="Unpinned ':latest' image tags weaken supply-chain integrity and rollback predictability.",
                    snippet=_snippet(lines, idx),
                    remediation="Pin container images to an immutable version tag or SHA256 digest.",
                )
            )

    return findings


def scan_iac_file(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    """Scan Terraform, Ansible, Kubernetes, Dockerfile, and Docker Compose configurations."""
    name = file_path.name.lower()
    suffix = file_path.suffix.lower()
    norm_rel = rel_path.replace("\\", "/").lower()

    if suffix == ".tf":
        return _scan_terraform(rel_path, content)
    if name == "dockerfile" or name.startswith("dockerfile."):
        return _scan_dockerfile(rel_path, content)
    if "docker-compose" in name and suffix in (".yml", ".yaml"):
        return _scan_compose(rel_path, content)
    if suffix in (".yml", ".yaml") and (
        "ansible" in norm_rel or "playbooks/" in norm_rel or "roles/" in norm_rel
    ):
        return _scan_ansible(rel_path, content)
    if suffix in (".yml", ".yaml") and (
        re.search(r"^apiVersion\s*:", content, re.MULTILINE)
        and re.search(r"^kind\s*:", content, re.MULTILINE)
    ):
        return _scan_kubernetes(rel_path, content)
    return []

