environment           = "prod"
aws_region            = "ap-southeast-1"
allowed_admin_cidrs   = ["10.20.0.0/16"]
app_instance_type     = "t3.large"
# g4dn.xlarge has 1x NVIDIA T4 (16GB VRAM) — fits 14B Q4_K_M / AWQ models cleanly
auditor_instance_type = "g4dn.xlarge"
model_profile         = "prod-16gb-coder"

