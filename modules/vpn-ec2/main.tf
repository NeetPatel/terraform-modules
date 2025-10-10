# VPN EC2 Instance Module
# This module creates an EC2 instance with OpenVPN server

# KMS Key for VPN secrets
resource "aws_kms_key" "vpn_secrets" {
  description             = "KMS key for VPN secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-vpn-secrets-kms"
  })
}

resource "aws_kms_alias" "vpn_secrets" {
  name          = "alias/${var.project_name}-${var.environment}-vpn-secrets"
  target_key_id = aws_kms_key.vpn_secrets.key_id
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

# Generate random password for OpenVPN
resource "random_password" "openvpn_password" {
  length  = 16
  special = true
}

# Store OpenVPN password in Secrets Manager
resource "aws_secretsmanager_secret" "openvpn_password" {
  name                    = "${var.project_name}-${var.environment}-vpn-password"
  description             = "OpenVPN server password"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.vpn_secrets.arn

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "openvpn_password" {
  secret_id     = aws_secretsmanager_secret.openvpn_password.id
  secret_string = jsonencode({
    password = random_password.openvpn_password.result
  })
}

# Security Group for VPN Server
resource "aws_security_group" "vpn_sg" {
  name_prefix = "${var.project_name}-${var.environment}-vpn-"
  description = "Security group for VPN server with OpenVPN access"
  vpc_id      = var.vpc_id

  # SSH access from allowed IPs
  dynamic "ingress" {
    for_each = var.allowed_ssh_cidrs
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
      description = "SSH access from ${ingress.value}"
    }
  }

  # OpenVPN UDP port
  ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
    description = "OpenVPN UDP"
  }

  # OpenVPN TCP port (backup)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
    description = "OpenVPN TCP"
  }

  # HTTP for OpenVPN admin interface
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
    description = "HTTP for OpenVPN admin"
  }

  # HTTPS for OpenVPN admin interface
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
    description = "HTTPS for OpenVPN admin"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-egress-sgr
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-vpn-sg"
  })
}

# Key Pair for VPN Server
resource "aws_key_pair" "vpn_key" {
  key_name   = "${var.project_name}-${var.environment}-vpn-key"
  public_key = var.public_ssh_key

  tags = local.common_tags
}

# EC2 Instance for VPN Server
resource "aws_instance" "vpn_server" {
  ami                    = var.ami_id != "" ? var.ami_id : "ami-07a3add10195338ad"  # Ubuntu 22.04 LTS us-east-1
  instance_type          = var.instance_type
  key_name              = aws_key_pair.vpn_key.key_name
  vpc_security_group_ids = [aws_security_group.vpn_sg.id]
  subnet_id             = var.subnet_id

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.volume_size
    encrypted             = true
    delete_on_termination = true
  }

  user_data = base64encode(templatefile("${path.module}/vpn-userdata.sh", {
    openvpn_password = random_password.openvpn_password.result
    vpn_client_name  = "${var.project_name}-${var.environment}-client"
  }))

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
  }

  monitoring = true

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-vpn-server"
    Type = "VPN-Server"
  })
}

# Elastic IP for VPN Server
resource "aws_eip" "vpn_eip" {
  instance = aws_instance.vpn_server.id
  domain   = "vpc"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-vpn-eip"
  })

  depends_on = [aws_instance.vpn_server]
}

# Store VPN connection details in Secrets Manager
resource "aws_secretsmanager_secret" "vpn_connection" {
  name                    = "${var.project_name}-${var.environment}-vpn-connection"
  description             = "VPN server connection details"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.vpn_secrets.arn

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "vpn_connection" {
  secret_id = aws_secretsmanager_secret.vpn_connection.id
  secret_string = jsonencode({
    server_ip     = aws_eip.vpn_eip.public_ip
    server_domain = aws_eip.vpn_eip.public_dns
    openvpn_port  = 1194
    admin_url     = "https://${aws_eip.vpn_eip.public_ip}:943/admin"
    client_url    = "https://${aws_eip.vpn_eip.public_ip}:943/"
    password      = random_password.openvpn_password.result
    ssh_key       = aws_key_pair.vpn_key.key_name
  })
}

# CloudWatch Log Group for VPN Server
resource "aws_cloudwatch_log_group" "vpn_logs" {
  name              = "/aws/ec2/${var.project_name}-${var.environment}-vpn"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.vpn_secrets.arn

  tags = local.common_tags
}

# Local values
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Module      = "vpn-ec2"
  }
}
