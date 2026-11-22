# Most cloud GPU node pools (EKS AL2023 GPU, GKE COS GPU, AKS GPU) pre-install NVIDIA drivers
deployment_target          = "cloud-k8s-nvidia"
model_profile              = "prod-16gb-coder"
enable_nvidia_gpu_operator = true
nvidia_install_host_driver = false
ollama_storage_size        = "50Gi"
