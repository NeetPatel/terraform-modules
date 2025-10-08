# EKS Module Variables

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
}

# VPC Configuration
variable "vpc_id" {
  description = "VPC ID where EKS cluster will be created"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for EKS cluster"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for ALB"
  type        = list(string)
}

# EKS Cluster Configuration
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = ""
}

variable "cluster_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.32"
}

variable "cluster_endpoint_private_access" {
  description = "Enable private access to EKS cluster API server"
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access" {
  description = "Enable public access to EKS cluster API server"
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks for public access to EKS cluster API server"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "cluster_enabled_log_types" {
  description = "List of enabled EKS cluster log types"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "cluster_encryption_config" {
  description = "EKS cluster encryption configuration"
  type = object({
    provider_key_arn = optional(string, null)
    resources        = optional(list(string), ["secrets"])
  })
  default = {
    provider_key_arn = null
    resources        = ["secrets"]
  }
}

# Node Group Configuration
variable "node_groups" {
  description = "Map of EKS managed node groups"
  type = map(object({
    instance_types = list(string)
    capacity_type  = optional(string, "ON_DEMAND")
    disk_size      = optional(number, 50)
    min_size       = optional(number, 1)
    max_size       = optional(number, 3)
    desired_size   = optional(number, 2)
    ami_type       = optional(string, "AL2_x86_64")
    labels = optional(map(string), {
      Environment = "pre-prod"
    })
    taints = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))
  default = {
    general = {
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      disk_size      = 50
      min_size       = 1
      max_size       = 3
      desired_size   = 2
      ami_type       = "AL2_x86_64"
      labels = {
        Environment = "pre-prod"
        NodeType    = "general"
      }
      taints = []
    }
  }
}

# ALB Configuration
variable "enable_alb" {
  description = "Enable Application Load Balancer"
  type        = bool
  default     = true
}

variable "alb_name" {
  description = "Name of the Application Load Balancer"
  type        = string
  default     = ""
}

variable "alb_scheme" {
  description = "ALB scheme (internal or internet-facing)"
  type        = string
  default     = "internet-facing"
  validation {
    condition     = contains(["internal", "internet-facing"], var.alb_scheme)
    error_message = "ALB scheme must be either 'internal' or 'internet-facing'."
  }
}

variable "alb_type" {
  description = "ALB type (application or network)"
  type        = string
  default     = "application"
  validation {
    condition     = contains(["application", "network"], var.alb_type)
    error_message = "ALB type must be either 'application' or 'network'."
  }
}

variable "alb_target_groups" {
  description = "Map of ALB target groups"
  type = map(object({
    port                 = number
    protocol             = string
    target_type          = optional(string, "ip")
    health_check_path    = optional(string, "/health")
    health_check_port    = optional(string, "traffic-port")
    health_check_protocol = optional(string, "HTTP")
    health_check_matcher = optional(string, "200")
    health_check_interval = optional(number, 30)
    health_check_timeout = optional(number, 5)
    healthy_threshold   = optional(number, 2)
    unhealthy_threshold = optional(number, 2)
    deregistration_delay = optional(number, 300)
    stickiness = optional(object({
      enabled = bool
      type    = string
    }), null)
  }))
  default = {
    web = {
      port                 = 80
      protocol             = "HTTP"
      target_type          = "ip"
      health_check_path    = "/health"
      health_check_port    = "traffic-port"
      health_check_protocol = "HTTP"
      health_check_matcher = "200"
      health_check_interval = 30
      health_check_timeout = 5
      healthy_threshold   = 2
      unhealthy_threshold = 2
      deregistration_delay = 300
      stickiness = {
        enabled = false
        type    = "lb_cookie"
      }
    }
  }
}

variable "alb_listeners" {
  description = "Map of ALB listeners"
  type = map(object({
    port            = number
    protocol        = string
    ssl_policy      = optional(string, null)
    certificate_arn = optional(string, null)
    default_action = object({
      type             = string
      target_group_key = optional(string, null)
      redirect = optional(object({
        port        = string
        protocol    = string
        status_code = string
      }), null)
    })
  }))
  default = {
    http = {
      port     = 80
      protocol = "HTTP"
      default_action = {
        type = "redirect"
        redirect = {
          port        = "443"
          protocol    = "HTTPS"
          status_code = "HTTP_301"
        }
      }
    }
    https = {
      port            = 443
      protocol        = "HTTPS"
      ssl_policy      = "ELBSecurityPolicy-TLS-1-2-2017-01"
      certificate_arn = null
      default_action = {
        type             = "forward"
        target_group_key = "web"
      }
    }
  }
}

# Security Configuration
variable "allowed_cidrs" {
  description = "CIDR blocks allowed to access ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_waf" {
  description = "Enable AWS WAF for ALB"
  type        = bool
  default     = false
}

variable "waf_web_acl_arn" {
  description = "ARN of WAF Web ACL to associate with ALB"
  type        = string
  default     = null
}

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate for HTTPS listener"
  type        = string
  default     = null
}

# Tags
variable "tags" {
  description = "Additional tags for EKS resources"
  type        = map(string)
  default     = {}
}

# External DNS Configuration
variable "enable_external_dns" {
  description = "Enable External DNS for automatic DNS management"
  type        = bool
  default     = true
}

variable "external_dns_version" {
  description = "External DNS version to deploy"
  type        = string
  default     = "1.13.1"
}

variable "external_dns_domain_filters" {
  description = "List of domains to filter DNS records"
  type        = list(string)
  default     = []
}

variable "external_dns_zone_type" {
  description = "Type of DNS zone (public or private)"
  type        = string
  default     = "public"
}

variable "external_dns_policy" {
  description = "External DNS policy (sync, upsert-only, create-only)"
  type        = string
  default     = "upsert-only"
}

variable "external_dns_txt_owner_id" {
  description = "TXT record owner ID for External DNS"
  type        = string
  default     = ""
}

variable "external_dns_txt_prefix" {
  description = "TXT record prefix for External DNS"
  type        = string
  default     = "external-dns"
}

variable "external_dns_annotation_filter" {
  description = "Annotation filter for External DNS"
  type        = string
  default     = "external-dns.alpha.kubernetes.io/hostname"
}

variable "external_dns_label_filter" {
  description = "Label filter for External DNS"
  type        = string
  default     = ""
}
