variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance (REQUIRED for dev)"
  type        = string
  
  validation {
    condition     = length(var.ami_id) > 0
    error_message = "AMI ID is required and cannot be empty in dev environment."
  }
}

variable "allowed_ssh_cidrs" {
  description = "List of CIDR blocks allowed to SSH to the instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "privileged_access_cidrs" {
  description = "List of CIDR blocks allowed privileged access (additional ports/services)"
  type        = list(string)
  default     = []
}

variable "public_ssh_keys" {
  description = "List of public SSH keys for EC2 access"
  type        = list(string)
  default     = []
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vpc_id" {
  description = "ID of the VPC where the instance will be created"
  type        = string
}

variable "subnet_id" {
  description = "ID of the subnet where the instance will be created"
  type        = string
}
