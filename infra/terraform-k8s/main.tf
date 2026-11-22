# ==============================================================================
# 1. Hardened Namespace (Platform-Agnostic Pod Security Admission)
# ==============================================================================
resource "kubernetes_namespace" "aiops" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of"          = "aiops-infra-auditor"
      "aiops.security/target"              = var.deployment_target
      "pod-security.kubernetes.io/enforce" = "baseline"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}

# ==============================================================================
# 2. Optional NVIDIA GPU Operator (On-Prem K8s & Cloud K8s Agnostic)
# ==============================================================================
resource "helm_release" "nvidia_gpu_operator" {
  count            = var.enable_nvidia_gpu_operator ? 1 : 0
  name             = "gpu-operator"
  repository       = "https://helm.ngc.nvidia.com/nvidia"
  chart            = "gpu-operator"
  version          = var.nvidia_gpu_operator_version
  namespace        = "gpu-operator"
  create_namespace = true
  wait             = true
  timeout          = 600

  set {
    name  = "driver.enabled"
    value = tostring(var.nvidia_install_host_driver)
  }

  set {
    name  = "toolkit.enabled"
    value = "true"
  }

  set {
    name  = "devicePlugin.enabled"
    value = "true"
  }

  set {
    name  = "nfd.enabled"
    value = "true"
  }

  set {
    name  = "dcgmExporter.enabled"
    value = "true"
  }
}

# ==============================================================================
# 3. Runtime Configuration & Reports PVC (Agnostic Default StorageClass)
# ==============================================================================
resource "kubernetes_config_map" "auditor_runtime" {
  metadata {
    name      = "aiops-auditor-terraform-meta"
    namespace = kubernetes_namespace.aiops.metadata[0].name
  }

  data = {
    DEPLOYMENT_TARGET   = var.deployment_target
    AIOPS_MODEL_PROFILE = var.model_profile
    NVIDIA_GPU_ENABLED  = tostring(var.enable_nvidia_gpu_operator)
  }
}

resource "kubernetes_persistent_volume_claim" "ollama_models_shared" {
  metadata {
    name      = "ollama-models-cache"
    namespace = kubernetes_namespace.aiops.metadata[0].name
  }

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = var.storage_class_name != "" ? var.storage_class_name : null
    resources {
      requests = {
        storage = var.ollama_storage_size
      }
    }
  }
}

