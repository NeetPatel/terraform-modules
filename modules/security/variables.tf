# Security Module Variables

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
  description = "VPC ID for flow logs"
  type        = string
}

variable "domain_name" {
  description = "Domain name for SSL certificate"
  type        = string
  default     = "example.com"
}

variable "subject_alternative_names" {
  description = "Subject alternative names for SSL certificate"
  type        = list(string)
  default     = ["*.example.com"]
}

variable "tags" {
  description = "Additional tags for security resources"
  type        = map(string)
  default     = {}
}
