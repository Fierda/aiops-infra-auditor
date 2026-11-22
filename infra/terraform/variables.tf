variable "project_name" {
  description = "Project identifier used for resource naming"
  type        = string
  default     = "aiops-infra-auditor"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "Target AWS region"
  type        = string
  default     = "ap-southeast-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.42.0.0/16"
}

variable "allowed_admin_cidrs" {
  description = "Trusted corporate/VPN CIDRs allowed to reach management endpoints (never 0.0.0.0/0)"
  type        = list(string)
  default     = ["10.0.0.0/8"]

  validation {
    condition     = !contains(var.allowed_admin_cidrs, "0.0.0.0/0")
    error_message = "0.0.0.0/0 is forbidden for allowed_admin_cidrs. Use VPN/bastion CIDRs or AWS SSM."
  }
}

variable "app_instance_type" {
  description = "EC2 instance type for the application workload"
  type        = string
  default     = "t3.medium"
}

variable "auditor_instance_type" {
  description = "EC2 instance type for AIOps Auditor (e.g., t3.xlarge for local-dev CPU, g4dn.xlarge [T4 16GB VRAM] or g5.xlarge [A10G 24GB VRAM] for prod <=16GB models)"
  type        = string
  default     = "g4dn.xlarge"
}

variable "model_profile" {
  description = "AIOps LLM profile passed to Ansible inventory (local-dev | prod-16gb-coder | prod-16gb-reasoning | prod-16gb-vllm)"
  type        = string
  default     = "prod-16gb-coder"
}

variable "ssh_key_name" {
  description = "Optional EC2 key pair name (prefer AWS SSM Session Manager in production)"
  type        = string
  default     = ""
}

