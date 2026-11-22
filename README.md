# AIOps Infra Auditor — Prod-Grade E2E Autonomous Security & Pre-Deploy Gate Pipeline

**AIOps Infra Auditor** adalah pipeline DevSecOps + AIOps *production-grade* yang menggabungkan **IaC (Terraform & Platform-Agnostic K8s)**, **Ansible Hardening & NVIDIA Runtime**, **Hardened App**, dan **Private Autonomous AI Security Agent** (open-source, pilihan model ringan untuk laptop & model `<= 16GB VRAM` untuk production).

Dirancang sebagai **Pre-Deploy & Config-Change Gatekeeper**: setiap kali **IaC**, **Ansible**, atau **App/Native Engine (PHP, Node.js, Java, Python, C, C++, Assembly, Rust FFI)** siap di-deploy atau mengubah konfigurasi server/cloud, auditor otomatis melakukan scan mendalam, memperbarui pengetahuan CVE terbaru (**CISA KEV + OSV.dev + NVD**), menjalankan **Autonomous ReAct AI Agent**, lalu **ALLOW** atau **BLOCK** deploy beserta saran mitigasi & patch.

---

## 1. E2E Change-Triggered Pre-Deploy Workflow

```mermaid
flowchart TD
    CHG["Code / Infra / Config Change Triggered"] --> SPLIT{"Layer yang Berubah?"}

    SPLIT -->|Terraform / K8s / Compose| G_IAC["Gate 1: aiops-auditor gate --stage iac"]
    SPLIT -->|Playbooks / Roles / Vars| G_ANS["Gate 2: aiops-auditor gate --stage ansible"]
    SPLIT -->|App / Native C-C++-ASM / Deps| G_APP["Gate 3: aiops-auditor gate --stage app"]

    G_IAC --> ENGINE["AIOps Hybrid Audit Engine"]
    G_ANS --> ENGINE
    G_APP --> ENGINE

    subgraph ENGINE ["AIOps Hybrid Audit Engine"]
        direction TB
        SYNC["Stage 0: Auto-Sync Live CVE KB (CISA KEV + OSV.dev + NVD)"]
        STATIC["Stage 1: Multi-Layer Discovery (SAST App + C/C++/ASM + Build Flags + SCA + IaC/K8s + Secrets)"]
        SLICE["Stage 2: Cross-File Caller Index & Context Slicing"]
        TRIAGE["Stage 3a: LLM Triage & Patch Agent (Anti-Prompt-Injection)"]
        REACT["Stage 3b: Autonomous ReAct Investigation Agent (Tool-Use Loop)"]
        SYNC --> STATIC --> SLICE --> TRIAGE --> REACT
    end

    REACT --> POLICY{"Policy Gate (>= HIGH / CRITICAL)?"}
    POLICY -->|"FAIL (Ada Celah)"| BLOCK["BLOCK Deploy / Config Change + Emit SARIF / MD / JSON + Patch"]
    POLICY -->|"PASS (0 Active >= HIGH)"| DEPLOY["ALLOW Deploy: Terraform Apply / Ansible Playbook / K8s Rollout"]
```

---

## 2. Cara Kerja AI Agent & Live CVE Self-Updating Loop

Model open-source lokal (3B / 14B `<= 16GB VRAM`) punya *knowledge cutoff* pada bobotnya. Sistem ini mengatasi hal itu dengan **Self-Updating Local CVE Knowledge Base** (`auditor/data/cve_kb.json`) + **Autonomous ReAct Tool-Use Loop** sehingga agent selalu tahu CVE hari ini dan bisa *hunting* celah logika/memori di luar regex statis:

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer / CI-CD / CronJob
    participant Orch as AIOps Orchestrator
    participant KB as Live CVE Knowledge Base (cve_kb.json)
    participant Feeds as CISA KEV / OSV.dev / NVD
    participant Scan as Static Scanners (App + C/C++/ASM + IaC)
    participant Agent as Autonomous AI Agent (3B Local / 14B <=16GB VRAM)

    Dev->>Orch: Trigger scan / pre-deploy gate (--auto-sync-cve)
    Orch->>Feeds: Fetch CISA KEV + OSV.dev (project deps) + optional NVD
    Feeds-->>KB: Persist brand-new CVEs, fixed versions & official mitigations
    Orch->>Scan: Run SAST (PHP/Node/Java/Py/C/C++/ASM), SCA (w/ Live KB), IaC/K8s, Secrets
    Scan-->>Orch: Candidate sinks, vulnerable deps & misconfigs

    loop Single-Shot Triage per Top Candidate
        Orch->>Agent: Nonce-wrapped code slice + imports + cross-file callers
        Agent-->>Orch: JSON Verdict (confirmed/false_positive + taint_analysis + patch)
    end

    loop Autonomous ReAct Hunting (max_agent_steps = 6)
        Agent->>Orch: Tool Call: list_attack_surfaces / read_code_slice / grep_symbol
        Orch-->>Agent: Nonce-fenced code snippet / cross-file call refs
        Agent->>KB: Tool Call: lookup_cve_intel (live CISA KEV / OSV / NVD)
        KB-->>Agent: Actively exploited CVEs + exact upgrade/mitigation steps
        Agent->>Orch: Tool Call: report_finding (new bug beyond static regex) / finish
    end

    Orch-->>Dev: Decision (ALLOW / BLOCK) + SARIF 2.1.0 + Markdown + JSON
```

---

## 3. Cakupan Deteksi Multi-Layer (High-Level sampai Low-Level Engine)

| Layer | Target / Ekosistem | Kelas Kerentanan yang Dideteksi |
| --- | --- | --- |
| **Web / App SAST** | PHP, Node.js/TS, Java, Python (AST) | `php2shell` (`unserialize`, dynamic `include`/PHAR, `shell_exec`, `eval`), `node2shell` (`child_process.exec`, `vm.runInNewContext`, prototype pollution), `java4shell` (JNDI `lookup`, `ObjectInputStream.readObject`, SpEL/OGNL/MVEL, Jackson `enableDefaultTyping`), Python (`yaml.load`, `pickle.loads`, `subprocess(..., shell=True)`) |
| **Low-Level Native & Engine** | C, C++, Assembly (`.s`/`.asm`/inline `__asm__`), Rust FFI (`.rs`), `Makefile`/`CMakeLists.txt`/`binding.gyp` | Buffer overflow (`strcpy`/`gets`/`sprintf`/`scanf`), Format string (`printf(var)`), Integer overflow di `malloc(a*b)`, Use-After-Free / Double-Free, raw `memcpy`/`alloca`, executable stack (`.note.GNU-stack,"x"`), raw `syscall`, Rust `unsafe`/`transmute`, build flags tidak hardened (`-fno-stack-protector`, `-z execstack`, `-no-pie`), base image runtime C-engine EOL (`php:7.4`, `node:16/18`, `python:3.8`) |
| **Open-Source SCA & Supply Chain** | `package.json`, `pom.xml`, `composer.json`, `requirements.txt` | Curated RCE CVEs (React2Shell `CVE-2025-55182`, Next.js `CVE-2025-29927`, Log4Shell `CVE-2021-44228`, Spring4Shell `CVE-2022-22965`) + **Live CISA KEV / OSV.dev / NVD KB** + malicious npm `preinstall`/`postinstall` pipe-to-shell hooks |
| **IaC & Container** | Terraform (`.tf`), Kubernetes YAML, Ansible, Dockerfile, Compose | SG `0.0.0.0/0` SSH/DB, unencrypted EBS/S3, IMDSv1, K8s `privileged: true`, `hostPID`/`hostNetwork`, `runAsUser: 0`, sensitive `hostPath` (`docker.sock`), RBAC wildcard `*`, Ansible `curl\|sh` / weak SSH / `validate_certs: false`, Dockerfile root / `:latest` |
| **Secrets & External Tools** | Semua file + SARIF 2.1.0 | AWS Access Keys, Private Keys, GitHub PAT, DB DSN (auto-redacted) + ingest SARIF eksternal dari **Semgrep / Trivy / Checkov** |
| **Autonomous AI Agent** | Lintas file & logika bisnis | Auth bypass, header spoofing, multi-hop taint chain antar file, validasi false positive, & auto-generate diff patch |

---

## 4. Open-Source Model Matrix (Local Test vs Prod `<= 16GB VRAM`)

Semua profile dikonfigurasi di [`auditor/config/models.yaml`](auditor/config/models.yaml).

> **Crucial VRAM Tuning (`<= 16GB VRAM`):** Untuk menjalankan model 14B dengan konteks 16K–32K secara stabil pada GPU 16GB (NVIDIA T4 16GB / RTX 4060 Ti 16GB / RTX 4080 16GB / A4000 16GB), pastikan environment berikut aktif (sudah diset otomatis di `docker-compose.yml`, `ansible/`, dan `k8s/`):
> - **Ollama**: `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0`, `OLLAMA_MAX_LOADED_MODELS=1`
> - **vLLM**: `--quantization awq_marlin --dtype half --gpu-memory-utilization 0.88 --max-model-len 16384 --enable-prefix-caching`

| Profile | Tier | Open-Source Model | Lisensi | Est. VRAM | Backend | Rekomendasi Penggunaan |
| --- | --- | --- | --- | ---: | --- | --- |
| `offline-heuristic` | Offline | Deterministic engine | Internal | 0 GB | Built-in | Air-gapped CI / fallback otomatis tanpa GPU |
| `local-tiny` | Local Test | `qwen2.5-coder:1.5b` | Apache-2.0 | 1.5 GB | Ollama | Smoke test super cepat di CPU |
| `local-dev` *(default)* | Local Test | `qwen2.5-coder:3b` | Apache-2.0 | 2.5 GB | Ollama | Testing harian di laptop (CPU / GPU 4GB) |
| `local-8gb` | Local Test | `qwen2.5-coder:7b` | Apache-2.0 | 5.8 GB | Ollama | GPU 8GB VRAM (RTX 3060 / 4060) |
| `prod-16gb-coder` | **Prod `<=16GB`** | `qwen2.5-coder:14b-instruct-q4_K_M` | Apache-2.0 | **12.5 GB** | Ollama | **Default Prod**: akurasi JSON, ReAct tool-use & patch terbaik |
| `prod-16gb-reasoning` | **Prod `<=16GB`** | `deepseek-r1:14b` | MIT | **12.8 GB** | Ollama | Deep reasoning untuk multi-hop taint & C/C++ memory chains |
| `prod-16gb-vllm` | **Prod `<=16GB`** | `Qwen/Qwen2.5-Coder-14B-Instruct-AWQ` | Apache-2.0 | **11.8 GB** | vLLM | High-throughput concurrent CI/CD serving |

---

## 5. Pilih Jalur Deployment (On-Prem, Local K8s, Cloud K8s Agnostic + NVIDIA)

Kamu **tidak perlu** memakai semua folder deploy sekaligus—pilih **1 jalur** sesuai infrastrukturmu:

| Target Infrastruktur | Stack yang Dipakai | NVIDIA GPU Support | Profile Default |
| --- | --- | --- | --- |
| **Laptop / 1 Server On-Prem (Docker)** | `docker-compose.yml` + `auditor/` | NVIDIA Container Toolkit (`--profile prod-gpu` / `prod-vllm`) | `local-dev` / `prod-16gb-coder` |
| **On-Prem VM / Bare Metal (Linux)** | `ansible/` (Debian/Ubuntu & RHEL/Rocky) | Role `nvidia_runtime` (Docker + `containerd`) | `prod-16gb-coder` |
| **AWS EC2 Provisioning + Hardening** | `infra/terraform/` → `ansible/` | `g4dn.xlarge` (NVIDIA T4 16GB VRAM) | `prod-16gb-coder` |
| **Local K8s (`kind` / `k3s` / `minikube`)** | `k8s/overlays/local-k8s` | CPU-only | `local-dev` |
| **On-Prem K8s (`k3s` / `kubeadm` / RKE2)** | `infra/terraform-k8s/` + `k8s/overlays/onprem-k8s-nvidia` | NVIDIA GPU Operator (`driver.enabled=true`) + DCGM | `prod-16gb-coder` |
| **Cloud K8s Agnostic (EKS / GKE / AKS / DOKS)** | `infra/terraform-k8s/` + `k8s/overlays/cloud-k8s-nvidia` | NVIDIA GPU Operator (`driver.enabled=false`) + Tolerations | `prod-16gb-coder` / `prod-16gb-vllm` |

---

## 6. Quick Start & Perintah Penting

### A. Verifikasi Lokal, Model List & Unit Tests
```powershell
$env:PYTHONPATH = "auditor\src"
python -m aiops_auditor models --vram-gb 16
python -m unittest discover -s tests -p "test_*.py" -v
```

### B. Sync Live CVE Knowledge Base (CISA KEV + NVD)
```powershell
$env:PYTHONPATH = "auditor\src"
python -m aiops_auditor sync-intel --include-nvd --keywords "php,node.js,openssl,spring,next.js,log4j"
```

### C. Pre-Deploy & Config-Change Gate (Blocking Wrapper)
```powershell
# Gate sebelum ubah IaC (Terraform / K8s)
.\scripts\deploy-gate.ps1 -Stage iac -Profile prod-16gb-coder -AutoSyncCve -DeployCommand "kubectl apply -k k8s/overlays/cloud-k8s-nvidia"

# Gate sebelum ubah konfigurasi server via Ansible (audit hanya file git diff)
.\scripts\deploy-gate.ps1 -Stage ansible -Profile prod-16gb-coder -ChangedOnly

# Gate sebelum build/deploy App + Native C/C++/ASM engine
.\scripts\deploy-gate.ps1 -Stage app -Profile local-dev -AutoSyncCve -EnableOsv

# Autoscan proyek open-source lain di komputer kamu
.\scripts\run-audit.ps1 -Target "D:\Code\project-kamu" -Profile local-dev -AutoSyncCve -EnableOsv
```

### D. Deploy Kubernetes (Local / On-Prem NVIDIA / Cloud K8s Agnostic)
```bash
# 1. Local K8s (CPU)
kubectl apply -k k8s/overlays/local-k8s

# 2. Install NVIDIA GPU Operator (On-Prem & Cloud K8s Agnostic)
helm repo add nvidia https://helm.ngc.nvidia.com/nvidia && helm repo update
helm upgrade --install gpu-operator nvidia/gpu-operator \
  -n gpu-operator --create-namespace \
  -f k8s/nvidia/gpu-operator-values.yaml

# 3a. On-Prem K8s + NVIDIA GPU (<=16GB VRAM)
kubectl apply -k k8s/overlays/onprem-k8s-nvidia

# 3b. Cloud K8s Agnostic (EKS / GKE / AKS / DOKS) + NVIDIA GPU
kubectl apply -k k8s/overlays/cloud-k8s-nvidia

# Opsional: High-throughput vLLM (Qwen2.5-Coder-14B-AWQ <=16GB VRAM)
kubectl apply -f k8s/overlays/cloud-k8s-nvidia/vllm-optional.yaml

# Jalankan audit on-demand di cluster kapan saja
kubectl -n aiops-auditor create job --from=cronjob/aiops-security-auditor manual-audit-1
```

### E. Terraform & Ansible
```bash
# Platform-Agnostic Terraform K8s + NVIDIA GPU Operator
cd infra/terraform-k8s && terraform init
terraform apply -var-file=environments/cloud-k8s-nvidia.tfvars

# VM Provisioning (AWS) + Ansible CIS Hardening & NVIDIA Container Toolkit
cd ../terraform && terraform init && terraform plan -var-file=environments/prod.tfvars
cd ../../ansible && ansible-playbook -i inventory/generated.ini playbooks/site.yml
```

---

## 7. Kontrol Keamanan Krusial (Production Checklist)

- **Anti-Prompt-Injection Defense**: Seluruh potongan kode dari repositori open-source yang diaudit dibungkus tag acak per-panggilan `<UNTRUSTED_CODE_<nonce>>` agar komentar jebakan (`// IGNORE PREVIOUS INSTRUCTIONS`) tidak bisa memanipulasi verdict AI Agent.
- **Strictly Defensive & Read-Only Tools**: Autonomous ReAct Agent hanya memiliki akses tool read-only (`list_attack_surfaces`, `read_code_slice`, `grep_symbol`, `lookup_cve_intel`, `report_finding`) dan dilarang menghasilkan payload eksploitasi atau shellcode.
- **Strict Mode vs Air-Gapped Fallback**:
  - Default lokal: jika Ollama/vLLM belum menyala, otomatis degrade dengan aman ke `HeuristicLLMClient` + mencatat peringatan di laporan.
  - Production CI ketat: aktifkan `--strict-llm` agar pipeline **wajib gagal** bila server GPU LLM tidak dapat dijangkau.
- **Hardened Infrastructure & Workloads**: IMDSv2 enforced, KMS CMK + key rotation, zero `0.0.0.0/0` SSH ingress, CIS SSH/sysctl/UFW/firewalld, K8s `NetworkPolicy` default-deny, Pod `runAsNonRoot` + `readOnlyRootFilesystem` + `cap_drop: ALL` + `seccompProfile: RuntimeDefault`.

---

## 8. Peta Direktori

```text
aiops-infra-auditor/
├── auditor/                   # Inti AIOps Security Auditor (Python stdlib, zero mandatory deps)
│   ├── config/                # models.yaml (3B local .. 14B <=16GB VRAM) & policy.yaml
│   └── src/aiops_auditor/
│       ├── scanners/          # code_sast, native_lowlevel (C/C++/ASM/Build), sca_deps, iac_scanner (TF/K8s/Ansible/Docker), secret_scanner, external_tools
│       ├── intel/             # cve_kb.py — Auto-sync CISA KEV + OSV.dev + NVD -> local cve_kb.json
│       ├── agents/            # orchestrator, investigator (ReAct tool loop), change_gate (iac/ansible/app), prompts
│       ├── llm/               # ollama_client, openai_compat (vLLM), heuristic_fallback
│       └── reporters/         # SARIF 2.1.0, Markdown, JSON
├── app/                       # Hardened sample microservice + isolated static audit test fixtures
├── k8s/                       # Platform-agnostic Kustomize base + overlays (local, onprem-nvidia, cloud-nvidia) + NVIDIA GPU Operator values
├── infra/
│   ├── terraform/             # AWS VPC + KMS + IMDSv2 + GPU EC2 -> auto-generates Ansible inventory
│   └── terraform-k8s/         # Platform-agnostic K8s + Helm NVIDIA GPU Operator provisioner
├── ansible/                   # Distro-agnostic CIS hardening (Debian/RHEL), NVIDIA Container Toolkit, app & auditor deploy
├── .github/workflows/         # E2E Change-Gated CI/CD (Gate App/Native + Gate IaC + Gate Ansible -> Deploy)
├── pipelines/                 # Self-hosted GitLab CI template (GPU runner support)
├── scripts/                   # deploy-gate.ps1/.sh, run-audit.ps1, pull-models.sh
└── tests/                     # Automated unit & integration tests (17 tests)
```
