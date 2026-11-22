output "vpc_id" {
  description = "Provisioned VPC ID"
  value       = aws_vpc.main.id
}

output "app_private_ip" {
  description = "Private IP of the Application host"
  value       = aws_instance.app.private_ip
}

output "auditor_private_ip" {
  description = "Private IP of the AIOps Security Auditor host"
  value       = aws_instance.auditor.private_ip
}

output "audit_reports_bucket" {
  description = "Encrypted S3 bucket for SARIF and JSON audit reports"
  value       = aws_s3_bucket.audit_reports.bucket
}

output "ansible_inventory_path" {
  description = "Auto-generated Ansible inventory path"
  value       = local_file.ansible_inventory.filename
}

