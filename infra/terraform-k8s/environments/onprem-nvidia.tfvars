# Set nvidia_install_host_driver = true if bare-metal nodes do not have NVIDIA drivers pre-installed
deployment_target          = "onprem-k8s-nvidia"
model_profile              = "prod-16gb-coder"
enable_nvidia_gpu_operator = true
nvidia_install_host_driver = true
ollama_storage_size        = "50Gi"
