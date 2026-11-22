# STATIC AUDIT TEST FIXTURE — Demonstrates IaC misconfigurations
resource "aws_security_group" "insecure_admin" {
  name = "fixture-insecure-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted_data" {
  availability_zone = "ap-southeast-1a"
  size              = 50
  encrypted         = false
}

