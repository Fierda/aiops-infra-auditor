terraform {
  required_version = ">= 1.7.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.17"
    }
  }
}

# Platform-agnostic Kubernetes & Helm providers:
# Works seamlessly with local K8s (kind/k3s/minikube), on-prem K8s (kubeadm/RKE2),
# and any Cloud K8s (EKS / GKE / AKS / DOKS / OVH) via standard kubeconfig.
provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kubeconfig_context != "" ? var.kubeconfig_context : null
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kubeconfig_context != "" ? var.kubeconfig_context : null
  }
}

