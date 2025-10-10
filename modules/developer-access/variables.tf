# Developer Access Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "developer_users" {
  description = "List of developer usernames"
  type        = list(string)
  default     = []
}

variable "developer_groups" {
  description = "List of developer group names"
  type        = list(string)
  default     = ["developers", "devops-team", "qa-team"]
}

variable "allowed_ip_ranges" {
  description = "List of IP ranges allowed for developer access"
  type        = list(string)
  default     = ["202.131.107.130/32", "202.131.110.138/32"]
}

variable "eks_cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "s3_bucket_arns" {
  description = "List of S3 bucket ARNs for readonly access"
  type        = list(string)
  default     = []
}

variable "aurora_cluster_identifier" {
  description = "Aurora cluster identifier"
  type        = string
}

variable "ecr_repository_arns" {
  description = "List of ECR repository ARNs"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
