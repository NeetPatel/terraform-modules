variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
}

variable "repositories" {
  description = "List of ECR repository configurations"
  type = list(object({
    name                 = string
    image_tag_mutability = optional(string, "MUTABLE")
    scan_on_push         = optional(bool, true)
    encryption_type      = optional(string, "AES256")
    kms_key_id          = optional(string, null)
    lifecycle_policy    = optional(string, null)
    custom_lifecycle_policy = optional(object({
      rules = list(object({
        rulePriority = number
        description  = string
        selection = object({
          tagStatus     = string
          tagPrefixList = optional(list(string), [])
          countType     = string
          countNumber   = number
        })
        action = object({
          type = string
        })
      }))
    }), null)
  }))
  default = []
}

variable "ecr_repository_names" {
  description = "Simple list of ECR repository names"
  type        = list(string)
  default     = []
}

variable "enable_lifecycle_policy" {
  description = "Enable default lifecycle policy for repositories"
  type        = bool
  default     = true
}

variable "default_lifecycle_policy" {
  description = "Default lifecycle policy configuration"
  type = object({
    max_image_count = number
    max_image_age   = number
  })
  default = {
    max_image_count = 10
    max_image_age   = 30
  }
}
