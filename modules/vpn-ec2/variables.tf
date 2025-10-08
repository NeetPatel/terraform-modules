# VPN EC2 Instance Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID where the VPN server will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID where the VPN server will be deployed"
  type        = string
}

variable "ami_id" {
  description = "AMI ID for the VPN server (if empty, will use latest Ubuntu 22.04)"
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "EC2 instance type for VPN server"
  type        = string
  default     = "t3a.micro"
}

variable "volume_size" {
  description = "Root volume size in GB"
  type        = number
  default     = 20
}

variable "allowed_ssh_cidrs" {
  description = "List of CIDR blocks allowed to SSH to the VPN server"
  type        = list(string)
  default     = []
}

variable "public_ssh_key" {
  description = "Public SSH key for VPN server access"
  type        = string
}

variable "vpn_client_name" {
  description = "Name for the VPN client user"
  type        = string
  default     = "vpn-client"
}

variable "tags" {
  description = "Additional tags for VPN resources"
  type        = map(string)
  default     = {}
}
