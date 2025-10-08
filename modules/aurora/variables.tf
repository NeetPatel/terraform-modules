variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC where Aurora will be created"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for Aurora"
  type        = list(string)
}

variable "ec2_security_group_id" {
  description = "Security group ID of the EC2 instance"
  type        = string
}

# Aurora Configuration
variable "database_name" {
  description = "Name of the initial Aurora database"
  type        = string
  default     = "devopsdb"
}

variable "master_username" {
  description = "Master username for Aurora"
  type        = string
  default     = "admin"
}

variable "engine_version" {
  description = "Aurora MySQL engine version"
  type        = string
  default     = "8.0.mysql_aurora.3.02.0"
}

variable "instance_class" {
  description = "Instance class for Aurora instances (Serverless v2)"
  type        = string
  default     = "db.serverless"
}

variable "instance_count" {
  description = "Number of Aurora instances"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum Aurora Serverless v2 capacity"
  type        = number
  default     = 16
}

variable "min_capacity" {
  description = "Minimum Aurora Serverless v2 capacity"
  type        = number
  default     = 0.5
}

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "Skip final snapshot when deleting"
  type        = bool
  default     = false
}
