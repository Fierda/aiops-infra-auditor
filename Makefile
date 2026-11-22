.PHONY: help test audit-local audit-prod audit-offline audit-fixtures gate-iac gate-ansible gate-app gate-all tf-validate tf-k8s-validate tf-plan ansible-lint pull-local-model pull-prod-model up-local up-prod down k8s-deploy-local k8s-deploy-onprem-gpu k8s-deploy-cloud-gpu nvidia-install-operator

PYTHON ?= python
TARGET ?= .
REPORT_DIR ?= reports

help:
	@echo "AIOps Infra Auditor - Prod-Grade DevSecOps Pipeline"
	@echo ""
	@echo "  make test              Run unit & integration tests"
	@echo "  make audit-offline     Run deterministic SAST/SCA/IaC/Secret audit (no LLM required)"
	@echo "  make audit-local       Run AI-assisted audit with small local model (local-dev)"
	@echo "  make audit-prod        Run AI-assisted audit with <=16GB VRAM prod model (prod-16gb-coder)"
	@echo "  make audit-fixtures    Run audit against isolated vulnerability pattern fixtures"
	@echo "  make pull-local-model  Pull small open-source model into Ollama"
	@echo "  make pull-prod-model   Pull <=16GB VRAM open-source model into Ollama"
	@echo "  make up-local          Start local stack (App + Ollama CPU + Auditor)"
	@echo "  make up-prod           Start prod GPU stack (App + Ollama GPU <=16GB VRAM + Auditor)"
	@echo "  make tf-validate       Validate Terraform IaC"
	@echo "  make tf-plan           Run Terraform plan (dev)"
	@echo "  make ansible-lint      Syntax-check Ansible playbooks"

test:
	PYTHONPATH=auditor/src $(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

audit-offline:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor scan --target $(TARGET) --profile offline-heuristic --out-dir $(REPORT_DIR)

audit-local:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor scan --target $(TARGET) --profile local-dev --out-dir $(REPORT_DIR)

audit-prod:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor scan --target $(TARGET) --profile prod-16gb-coder --out-dir $(REPORT_DIR)

audit-fixtures:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor scan --target app/samples_for_audit_test --profile offline-heuristic --out-dir $(REPORT_DIR)/fixtures --no-fail

gate-iac:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor gate --stage iac --repo . --profile local-dev --out-dir $(REPORT_DIR)

gate-ansible:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor gate --stage ansible --repo . --profile local-dev --out-dir $(REPORT_DIR)

gate-app:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor gate --stage app --repo . --profile local-dev --out-dir $(REPORT_DIR)

gate-all:
	PYTHONPATH=auditor/src $(PYTHON) -m aiops_auditor gate --stage all --repo . --profile prod-16gb-coder --out-dir $(REPORT_DIR)

pull-local-model:
	bash scripts/pull-models.sh local-dev

pull-prod-model:
	bash scripts/pull-models.sh prod-16gb-coder

up-local:
	docker compose --profile local up -d --build

up-prod:
	docker compose --profile prod-gpu up -d --build

down:
	docker compose --profile local --profile prod-gpu down

tf-validate:
	cd infra/terraform && terraform init -backend=false && terraform validate

tf-k8s-validate:
	cd infra/terraform-k8s && terraform init -backend=false && terraform validate

tf-plan:
	cd infra/terraform && terraform plan -var-file=environments/dev.tfvars

ansible-lint:
	cd ansible && ansible-playbook --syntax-check playbooks/site.yml

nvidia-install-operator:
	helm repo add nvidia https://helm.ngc.nvidia.com/nvidia && helm repo update
	helm upgrade --install gpu-operator nvidia/gpu-operator -n gpu-operator --create-namespace -f k8s/nvidia/gpu-operator-values.yaml

k8s-deploy-local:
	kubectl apply -k k8s/overlays/local-k8s

k8s-deploy-onprem-gpu:
	kubectl apply -k k8s/overlays/onprem-k8s-nvidia

k8s-deploy-cloud-gpu:
	kubectl apply -k k8s/overlays/cloud-k8s-nvidia

