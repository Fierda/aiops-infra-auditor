"""Tests for SAST (PHP/Node/Java/Python), SCA, IaC, and Secret scanners."""

from __future__ import annotations

import unittest
from pathlib import Path

from aiops_auditor.scanners import (
    scan_dependency_manifest,
    scan_iac_file,
    scan_native_lowlevel,
    scan_secrets,
    scan_source_code,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "app" / "samples_for_audit_test"


class TestMultiEcosystemScanners(unittest.TestCase):
    def test_php2shell_detection_and_safe_guard(self) -> None:
        php_file = FIXTURES_DIR / "legacy_php_handler.php"
        findings = scan_source_code(php_file, php_file.name, php_file.read_text(encoding="utf-8"))
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PHP-RCE-001", rule_ids)  # unserialize
        self.assertIn("PHP-RCE-002", rule_ids)  # dynamic include
        self.assertIn("PHP-RCE-003", rule_ids)  # shell_exec

        # Safe unserialize with allowed_classes => false should not trigger PHP-RCE-001
        safe_php = "<?php $obj = unserialize($raw, ['allowed_classes' => false]);"
        safe_findings = scan_source_code(Path("safe.php"), "safe.php", safe_php)
        self.assertEqual(safe_findings, [])

    def test_node2shell_sast_and_rsc_sca(self) -> None:
        js_file = FIXTURES_DIR / "node_route_handler.js"
        sast_findings = scan_source_code(js_file, js_file.name, js_file.read_text(encoding="utf-8"))
        rule_ids = {f.rule_id for f in sast_findings}
        self.assertIn("NODE-RCE-001", rule_ids)  # child_process exec
        self.assertIn("NODE-RCE-002", rule_ids)  # vm.runInNewContext
        self.assertIn("NODE-PP-004", rule_ids)  # prototype pollution

        pkg_file = FIXTURES_DIR / "package.json"
        sca_findings = scan_dependency_manifest(
            pkg_file, pkg_file.name, pkg_file.read_text(encoding="utf-8")
        )
        cves = {f.cve for f in sca_findings if f.cve}
        sca_rules = {f.rule_id for f in sca_findings}
        self.assertIn("CVE-2025-55182", cves)  # React2Shell / RSC
        self.assertIn("CVE-2025-29927", cves)  # Next.js
        self.assertIn("CVE-2020-8203", cves)   # Lodash
        self.assertIn("SCA-NPM-SUPPLYCHAIN-001", sca_rules)

    def test_java4shell_sast_and_maven_sca(self) -> None:
        java_file = FIXTURES_DIR / "LegacyServiceController.java"
        sast_findings = scan_source_code(
            java_file, java_file.name, java_file.read_text(encoding="utf-8")
        )
        rule_ids = {f.rule_id for f in sast_findings}
        self.assertIn("JAVA-RCE-001", rule_ids)  # JNDI lookup
        self.assertIn("JAVA-RCE-002", rule_ids)  # ObjectInputStream.readObject
        self.assertIn("JAVA-RCE-003", rule_ids)  # SpEL parseExpression

        pom_file = FIXTURES_DIR / "pom.xml"
        sca_findings = scan_dependency_manifest(
            pom_file, pom_file.name, pom_file.read_text(encoding="utf-8")
        )
        cves = {f.cve for f in sca_findings}
        self.assertIn("CVE-2021-44228", cves)  # Log4Shell
        self.assertIn("CVE-2022-22965", cves)  # Spring4Shell

    def test_python_ast_scanner(self) -> None:
        py_file = FIXTURES_DIR / "unsafe_python_worker.py"
        findings = scan_source_code(py_file, py_file.name, py_file.read_text(encoding="utf-8"))
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PY-RCE-001", rule_ids)  # yaml.load
        self.assertIn("PY-RCE-002", rule_ids)  # pickle.loads
        self.assertIn("PY-RCE-003", rule_ids)  # subprocess shell=True

        safe_py = "import yaml, subprocess\n# yaml.load(x) in comment\ndata = yaml.safe_load('a: 1')\nsubprocess.run(['echo', 'ok'], shell=False)\n"
        self.assertEqual(scan_source_code(Path("safe.py"), "safe.py", safe_py), [])

    def test_iac_scanner_catches_insecure_fixture_and_passes_prod_infra(self) -> None:
        insecure_tf = FIXTURES_DIR / "insecure_infra.tf"
        tf_findings = scan_iac_file(
            insecure_tf, insecure_tf.name, insecure_tf.read_text(encoding="utf-8")
        )
        rule_ids = {f.rule_id for f in tf_findings}
        self.assertIn("IAC-TF-001", rule_ids)  # 0.0.0.0/0 SSH
        self.assertIn("IAC-TF-002", rule_ids)  # encrypted = false

        # Verify our own prod Terraform, Dockerfiles, and Ansible pass with zero findings
        prod_files = [
            REPO_ROOT / "infra" / "terraform" / "main.tf",
            REPO_ROOT / "infra" / "terraform-k8s" / "main.tf",
            REPO_ROOT / "app" / "Dockerfile",
            REPO_ROOT / "auditor" / "Dockerfile",
            REPO_ROOT / "docker-compose.yml",
            REPO_ROOT / "ansible" / "roles" / "security_hardening" / "tasks" / "main.yml",
            REPO_ROOT / "ansible" / "roles" / "nvidia_runtime" / "tasks" / "main.yml",
        ]
        for pf in prod_files:
            rel = pf.relative_to(REPO_ROOT).as_posix()
            res = scan_iac_file(pf, rel, pf.read_text(encoding="utf-8"))
            self.assertEqual(res, [], f"Expected 0 IaC findings in hardened file {rel}, got {res}")

    def test_kubernetes_manifest_scanner_catches_fixture_and_passes_prod_k8s(self) -> None:
        insecure_k8s = FIXTURES_DIR / "insecure_k8s_deploy.yaml"
        findings = scan_iac_file(
            insecure_k8s, insecure_k8s.name, insecure_k8s.read_text(encoding="utf-8")
        )
        rule_ids = {f.rule_id for f in findings}
        for expected_rule in (
            "IAC-K8S-001",  # privileged: true
            "IAC-K8S-002",  # hostPID: true
            "IAC-K8S-003",  # runAsUser: 0
            "IAC-K8S-004",  # allowPrivilegeEscalation: true
            "IAC-K8S-005",  # hostPath /var/run/docker.sock
            "IAC-K8S-006",  # RBAC wildcard *
            "IAC-K8S-007",  # image: nginx:latest
        ):
            self.assertIn(expected_rule, rule_ids)

        # Verify all production K8s manifests across base & overlays pass with 0 findings
        k8s_dir = REPO_ROOT / "k8s"
        k8s_files = list(k8s_dir.rglob("*.yaml"))
        self.assertGreaterEqual(len(k8s_files), 10)
        for kf in k8s_files:
            rel = kf.relative_to(REPO_ROOT).as_posix()
            res = scan_iac_file(kf, rel, kf.read_text(encoding="utf-8"))
            self.assertEqual(res, [], f"Expected 0 K8s findings in {rel}, got {res}")

    def test_secret_scanner_redacts_secrets(self) -> None:
        fake_key = "AWS_KEY=" + "AKIA" + "IOSFODNN7EXAMPLE"
        findings = scan_secrets(Path("config.py"), "config.py", fake_key)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-001")
        self.assertIn("[REDACTED_SECRET]", findings[0].snippet)
        self.assertNotIn("IOSFODNN7EXAMPLE", findings[0].snippet)

    def test_native_c_cpp_asm_build_and_eol_engine_scanner(self) -> None:
        c_file = FIXTURES_DIR / "native_parser_addon.c"
        c_findings = scan_native_lowlevel(c_file, c_file.name, c_file.read_text(encoding="utf-8"))
        c_rules = {f.rule_id for f in c_findings}
        self.assertIn("NAT-C-001", c_rules)    # strcpy buffer overflow
        self.assertIn("NAT-C-002", c_rules)    # format string printf(user_header)
        self.assertIn("NAT-C-004", c_rules)    # integer multiplication in malloc
        self.assertIn("NAT-C-006", c_rules)    # UAF after free(heap_buf)
        self.assertIn("NAT-ASM-001", c_rules)  # inline __asm__

        asm_file = FIXTURES_DIR / "legacy_lowlevel.s"
        asm_findings = scan_native_lowlevel(
            asm_file, asm_file.name, asm_file.read_text(encoding="utf-8")
        )
        asm_rules = {f.rule_id for f in asm_findings}
        self.assertIn("NAT-ASM-002", asm_rules)  # executable GNU-stack
        self.assertIn("NAT-ASM-003", asm_rules)  # raw syscall

        mk_file = FIXTURES_DIR / "legacy_build.Makefile"
        mk_findings = scan_native_lowlevel(
            mk_file, mk_file.name, mk_file.read_text(encoding="utf-8")
        )
        mk_rules = {f.rule_id for f in mk_findings}
        self.assertIn("NAT-BUILD-001", mk_rules)  # -fno-stack-protector / -z,execstack
        self.assertIn("NAT-BUILD-002", mk_rules)  # -no-pie

        eol_df = FIXTURES_DIR / "Dockerfile.eol_engine"
        eol_findings = scan_native_lowlevel(
            eol_df, eol_df.name, eol_df.read_text(encoding="utf-8")
        )
        self.assertIn("NAT-ENGINE-001", {f.rule_id for f in eol_findings})


if __name__ == "__main__":
    unittest.main()

