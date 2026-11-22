#!/usr/bin/env bash
# E2E Pre-Deploy & Config-Change Gate Wrapper
# Blocks Terraform apply, K8s deploy, Ansible config changes, or App builds if AIOps Auditor fails.
#
# Usage:
#   bash scripts/deploy-gate.sh iac      prod-16gb-coder  -- kubectl apply -k k8s/overlays/cloud-k8s-nvidia
#   bash scripts/deploy-gate.sh ansible  prod-16gb-coder  -- ansible-playbook -i ansible/inventory/generated.ini ansible/playbooks/site.yml
#   bash scripts/deploy-gate.sh app      local-dev        -- docker build -t aiops-sample-app:latest ./app

set -euo pipefail

STAGE="${1:-all}"
PROFILE="${2:-local-dev}"
shift 2 || true
if [[ "${1:-}" == "--" ]]; then
  shift
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[AIOPS-GATE] Running Pre-Deploy / Config-Change Audit (stage=${STAGE}, profile=${PROFILE})..."
PYTHONPATH="${REPO_ROOT}/auditor/src" python3 -m aiops_auditor gate \
  --stage "${STAGE}" \
  --repo "${REPO_ROOT}" \
  --profile "${PROFILE}" \
  --out-dir "${REPO_ROOT}/reports"

if [[ $# -gt 0 ]]; then
  echo "[AIOPS-GATE] Gate PASSED. Executing deployment/change command: $*"
  exec "$@"
else
  echo "[AIOPS-GATE] Gate PASSED (dry-run; no deploy command provided)."
fi

