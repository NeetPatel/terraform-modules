# dev CONFIGURATION: Using specific AMI ID only
# Dynamic AMI lookup removed for dev stability
# Always use tested and approved AMI IDs in dev environments

# Generate TLS private key for EC2 (if no public keys provided)
resource "tls_private_key" "ec2_key" {
  count     = length(var.public_ssh_keys) == 0 ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create AWS key pairs for multiple keys
resource "aws_key_pair" "ec2_keys" {
  count      = length(var.public_ssh_keys)
  key_name   = "${var.project_name}-ec2-key-${count.index + 1}"
  public_key = var.public_ssh_keys[count.index]
}

# Create AWS key pair for generated key
resource "aws_key_pair" "ec2_generated_key" {
  count      = length(var.public_ssh_keys) == 0 ? 1 : 0
  key_name   = "${var.project_name}-ec2-generated-key"
  public_key = tls_private_key.ec2_key[0].public_key_openssh
}

# Security Group with restrictive rules
resource "aws_security_group" "ec2_sg" {
  name_prefix = "${var.project_name}-ec2-sg-"
  description = "Security group for EC2 instance with restricted access"
  vpc_id      = var.vpc_id

  # HTTP inbound rule - allow from all IPs
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
  }

  # HTTPS inbound rule - allow from all IPs
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
  }

  # Jenkins inbound rule - allow from all IPs
  ingress {
    description = "Jenkins"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
  }

  # SSH inbound rule - restricted to specific IPs
  dynamic "ingress" {
    for_each = var.allowed_ssh_cidrs
    content {
      description = "SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  # Privileged access rules - specific ports for VPN access
  dynamic "ingress" {
    for_each = var.privileged_access_cidrs
    content {
      description = "Privileged Access - SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  # Additional privileged ports for specific services
  dynamic "ingress" {
    for_each = var.privileged_access_cidrs
    content {
      description = "Privileged Access - HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  dynamic "ingress" {
    for_each = var.privileged_access_cidrs
    content {
      description = "Privileged Access - HTTP"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  # Outbound rules - allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-egress-sgr
  }

  tags = {
    Name        = "${var.project_name}-ec2-sg"
    Environment = var.environment
    Project     = var.project_name
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Get availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# EC2 Instance
resource "aws_instance" "ec2_instance" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name = length(var.public_ssh_keys) > 0 ? aws_key_pair.ec2_keys[0].key_name : aws_key_pair.ec2_generated_key[0].key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  subnet_id              = var.subnet_id

  # User data script for Jenkins setup
  user_data = base64encode(file("${path.module}/setup_jenkins.sh"))

  # Enable detailed monitoring
  monitoring = true

  # Metadata options for security
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
  }

  # Root volume configuration
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true

    tags = {
      Name        = "${var.project_name}-root-volume"
      Environment = var.environment
      Project     = var.project_name
    }
  }

  tags = {
    Name        = "${var.project_name}-ec2-instance"
    Environment = var.environment
    Project     = var.project_name
  }

  lifecycle {
    create_before_destroy = true
  }
}

# No need for default subnet data source - using provided subnet_id

# Elastic IP
resource "aws_eip" "ec2_eip" {
  instance = aws_instance.ec2_instance.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-elastic-ip"
    Environment = var.environment
    Project     = var.project_name
  }

  depends_on = [aws_instance.ec2_instance]
}
