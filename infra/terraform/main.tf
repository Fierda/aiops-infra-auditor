data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_ami" "ubuntu_2404" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  az_primary  = data.aws_availability_zones.available.names[0]
}

# ==============================================================================
# KMS Customer Managed Key (EBS + Audit Report Encryption)
# ==============================================================================
resource "aws_kms_key" "infra" {
  description             = "CMK for ${local.name_prefix} EBS volumes and security audit artifacts"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "infra" {
  name          = "alias/${local.name_prefix}-cmk"
  target_key_id = aws_kms_key.infra.key_id
}

# ==============================================================================
# Network Layer (VPC, Public/Private Subnets, NAT, Flow Logs)
# ==============================================================================
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = local.az_primary
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-public-a" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 10)
  availability_zone       = local.az_primary
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-private-a" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${local.name_prefix}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  depends_on    = [aws_internet_gateway.igw]
  tags          = { Name = "${local.name_prefix}-nat" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ==============================================================================
# Security Groups (Least-Privilege, Zero 0.0.0.0/0 Management Exposure)
# ==============================================================================
resource "aws_security_group" "app" {
  name        = "${local.name_prefix}-app-sg"
  description = "Least-privilege SG for application host"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS/App traffic from trusted admin/ALB CIDRs"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
  }

  egress {
    description = "Outbound HTTPS for updates/telemetry"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "auditor" {
  name        = "${local.name_prefix}-auditor-sg"
  description = "Private GPU/CPU AIOps Auditor host (no public ingress)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Internal SSH/Ansible management from trusted VPN CIDR only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_admin_cidrs
  }

  egress {
    description = "Outbound HTTPS for model downloads and OSV advisory queries"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ==============================================================================
# Encrypted S3 Bucket for Security Audit Reports (SARIF / JSON / SBOM)
# ==============================================================================
resource "aws_s3_bucket" "audit_reports" {
  bucket = "${local.name_prefix}-reports-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.infra.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_reports" {
  bucket                  = aws_s3_bucket.audit_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==============================================================================
# IAM Least-Privilege Instance Profile (SSM + Audit Bucket PutObject only)
# ==============================================================================
resource "aws_iam_role" "node" {
  name = "${local.name_prefix}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "audit_upload" {
  name = "${local.name_prefix}-audit-upload"
  role = aws_iam_role.node.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.audit_reports.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.infra.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "node" {
  name = "${local.name_prefix}-node-profile"
  role = aws_iam_role.node.name
}

# ==============================================================================
# Compute Layer: App Host + GPU AIOps Auditor Host (IMDSv2 + Encrypted EBS)
# ==============================================================================
resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu_2404.id
  instance_type          = var.app_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.node.name
  key_name               = var.ssh_key_name != "" ? var.ssh_key_name : null

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
    kms_key_id  = aws_kms_key.infra.arn
  }

  tags = {
    Name = "${local.name_prefix}-app"
    Role = "app"
  }
}

resource "aws_instance" "auditor" {
  ami                    = data.aws_ami.ubuntu_2404.id
  instance_type          = var.auditor_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.auditor.id]
  iam_instance_profile   = aws_iam_instance_profile.node.name
  key_name               = var.ssh_key_name != "" ? var.ssh_key_name : null

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 100 # Space for <=16GB VRAM quantized open-source LLM weights + Docker images
    encrypted   = true
    kms_key_id  = aws_kms_key.infra.arn
  }

  tags = {
    Name = "${local.name_prefix}-auditor"
    Role = "aiops-auditor"
  }
}

# ==============================================================================
# IaC -> Ansible Bridge: Auto-Generate Dynamic Inventory
# ==============================================================================
resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/templates/inventory.ini.tpl", {
    app_private_ip     = aws_instance.app.private_ip
    auditor_private_ip = aws_instance.auditor.private_ip
    environment        = var.environment
    model_profile      = var.model_profile
    audit_bucket       = aws_s3_bucket.audit_reports.bucket
  })
  filename        = "${path.module}/../../ansible/inventory/generated.ini"
  file_permission = "0600"
}

