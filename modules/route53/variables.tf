# Route53 Module Variables

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

variable "hosted_zones" {
  description = "Map of Route53 hosted zones to create"
  type = map(object({
    domain_name = string
    comment     = optional(string, "")
  }))
  default = {}
}

variable "dns_records" {
  description = "Map of DNS records to create"
  type = map(object({
    zone_key = string
    name     = string
    type     = string
    ttl      = number
    records  = list(string)
  }))
  default = {}
}

variable "health_checks" {
  description = "Map of Route53 health checks to create"
  type = map(object({
    fqdn                            = string
    port                            = optional(number, 80)
    type                            = optional(string, "HTTP")
    resource_path                   = optional(string, "/")
    failure_threshold               = optional(number, 3)
    request_interval                = optional(number, 30)
    cloudwatch_alarm_region         = optional(string, "")
    cloudwatch_alarm_name           = optional(string, "")
    insufficient_data_health_status = optional(string, "Healthy")
  }))
  default = {}
}

variable "tags" {
  description = "Additional tags for Route53 resources"
  type        = map(string)
  default     = {}
}
