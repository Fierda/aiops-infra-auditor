output "namespace" {
  description = "Provisioned Kubernetes namespace"
  value       = kubernetes_namespace.aiops.metadata[0].name
}

output "kustomize_overlay_command" {
  description = "Next command to deploy workloads using the matching Kustomize overlay"
  value       = "kubectl apply -k k8s/overlays/${var.deployment_target}"
}

output "nvidia_gpu_operator_enabled" {
  description = "Whether NVIDIA GPU Operator Helm release was provisioned"
  value       = var.enable_nvidia_gpu_operator
}

