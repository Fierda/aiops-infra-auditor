variable "kubeconfig_path" {
  description = "Path to kubeconfig file (works for local k3s/kind, on-prem K8s, EKS, GKE, AKS)"
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Optional kubeconfig context name (empty = current-context)"
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Kubernetes namespace for AIOps Infra Auditor workloads"
  type        = string
  default     = "aiops-auditor"
}

variable "deployment_target" {
  description = "Target cluster profile: local-k8s | onprem-k8s-nvidia | cloud-k8s-nvidia"
  type        = string
  default     = "cloud-k8s-nvidia"

  validation {
    condition     = contains(["local-k8s", "onprem-k8s-nvidia", "cloud-k8s-nvidia"], var.deployment_target)
    error_message = "deployment_target must be one of: local-k8s, onprem-k8s-nvidia, cloud-k8s-nvidia."
  }
}

variable "model_profile" {
  description = "AIOps open-source LLM profile (local-dev | prod-16gb-coder | prod-16gb-reasoning | prod-16gb-vllm)"
  type        = string
  default     = "prod-16gb-coder"
}

variable "enable_nvidia_gpu_operator" {
  description = "Install NVIDIA GPU Operator via Helm (enable for bare-metal/cloud K8s nodes with NVIDIA GPUs)"
  type        = bool
  default     = true
}

variable "nvidia_install_host_driver" {
  description = "Let GPU Operator install NVIDIA kernel driver (true on bare-metal on-prem without driver; false on cloud GPU AMIs/COS)"
  type        = bool
  default     = false
}

variable "nvidia_gpu_operator_version" {
  description = "Pinned NVIDIA GPU Operator Helm chart version"
  type        = string
  default     = "v24.9.1"
}

variable "storage_class_name" {
  description = "Optional StorageClass name (empty = cluster default StorageClass, cloud/on-prem agnostic)"
  type        = string
  default     = ""
}

variable "ollama_storage_size" {
  description = "PVC size for cached open-source LLM weights"
  type        = string
  default     = "40Gi"
}

