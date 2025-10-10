variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
  default     = "devops-test"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3a.micro"
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
  description = "List of CIDR blocks allowed to SSH to the instance (REQUIRED for dev)"
  type        = list(string)

  validation {
    condition     = length(var.allowed_ssh_cidrs) > 0
    error_message = "At least one SSH CIDR block must be specified for dev security."
  }

  validation {
    condition     = !contains(var.allowed_ssh_cidrs, "0.0.0.0/0")
    error_message = "SSH access from all IPs (0.0.0.0/0) is not allowed in dev environment."
  }
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

# VPC Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

# S3 Configuration
variable "s3_bucket_name" {
  description = "Name of the S3 bucket (will be prefixed with project and environment)"
  type        = string
  default     = "assets"
}

variable "s3_buckets" {
  description = "List of S3 bucket configurations"
  type = list(object({
    name                = string
    enable_versioning   = optional(bool, true)
    block_public_access = optional(bool, true)
    enable_cloudfront   = optional(bool, true)
    default_root_object = optional(string, "index.html")
    price_class         = optional(string, "PriceClass_100")
  }))
  default = []
}

variable "s3_bucket_names" {
  description = "Simple list of S3 bucket names"
  type        = list(string)
  default     = []
}

variable "s3_environment_buckets" {
  description = "Environment-specific bucket configurations"
  type = map(object({
    bucket_names        = list(string)
    enable_cloudfront   = optional(bool, true)
    enable_versioning   = optional(bool, true)
    block_public_access = optional(bool, true)
  }))
  default = {}
}

variable "s3_enable_versioning" {
  description = "Enable S3 bucket versioning (for single bucket)"
  type        = bool
  default     = true
}

variable "s3_block_public_access" {
  description = "Block public access to S3 bucket (for single bucket)"
  type        = bool
  default     = true
}

variable "s3_default_root_object" {
  description = "Default root object for CloudFront distribution (for single bucket)"
  type        = string
  default     = "index.html"
}

variable "s3_price_class" {
  description = "CloudFront price class (for single bucket)"
  type        = string
  default     = "PriceClass_100"
  validation {
    condition = contains([
      "PriceClass_All",
      "PriceClass_200",
      "PriceClass_100"
    ], var.s3_price_class)
    error_message = "Price class must be one of: PriceClass_All, PriceClass_200, PriceClass_100."
  }
}

# Aurora Configuration
variable "aurora_database_name" {
  description = "Name of the initial Aurora database"
  type        = string
  default     = "devopsdb"
}

variable "aurora_master_username" {
  description = "Master username for Aurora"
  type        = string
  default     = "admin"
}

variable "aurora_engine_version" {
  description = "Aurora MySQL engine version"
  type        = string
  default     = "8.0.mysql_aurora.3.02.0"
}

variable "aurora_instance_class" {
  description = "Instance class for Aurora instances (Serverless v2)"
  type        = string
  default     = "db.serverless"
}

variable "aurora_instance_count" {
  description = "Number of Aurora instances"
  type        = number
  default     = 1
}

variable "aurora_max_capacity" {
  description = "Maximum Aurora Serverless v2 capacity"
  type        = number
  default     = 16
}

variable "aurora_min_capacity" {
  description = "Minimum Aurora Serverless v2 capacity"
  type        = number
  default     = 0.5
}

variable "aurora_backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "aurora_deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
  default     = true
}

variable "aurora_skip_final_snapshot" {
  description = "Skip final snapshot when deleting"
  type        = bool
  default     = false
}

# ECR Configuration
variable "ecr_repositories" {
  description = "List of ECR repository configurations"
  type = list(object({
    name                 = string
    image_tag_mutability = optional(string, "MUTABLE")
    scan_on_push         = optional(bool, true)
    encryption_type      = optional(string, "AES256")
    kms_key_id           = optional(string, null)
    lifecycle_policy     = optional(string, null)
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

variable "ecr_enable_lifecycle_policy" {
  description = "Enable default lifecycle policy for repositories"
  type        = bool
  default     = true
}

variable "ecr_default_lifecycle_policy" {
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

# EKS Configuration
variable "eks_cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = ""
}

variable "eks_cluster_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.32"
}

variable "eks_cluster_endpoint_private_access" {
  description = "Enable private access to EKS cluster API server"
  type        = bool
  default     = true
}

variable "eks_cluster_endpoint_public_access" {
  description = "Enable public access to EKS cluster API server"
  type        = bool
  default     = true
}

variable "eks_cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks for public access to EKS cluster API server"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "eks_cluster_enabled_log_types" {
  description = "List of enabled EKS cluster log types"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "eks_cluster_encryption_config" {
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

variable "eks_node_groups" {
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
      instance_types = ["t3a.medium"]
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

variable "eks_enable_alb" {
  description = "Enable Application Load Balancer"
  type        = bool
  default     = true
}

variable "eks_alb_name" {
  description = "Name of the Application Load Balancer"
  type        = string
  default     = ""
}

variable "eks_alb_scheme" {
  description = "ALB scheme (internal or internet-facing)"
  type        = string
  default     = "internet-facing"
  validation {
    condition     = contains(["internal", "internet-facing"], var.eks_alb_scheme)
    error_message = "ALB scheme must be either 'internal' or 'internet-facing'."
  }
}

variable "eks_alb_type" {
  description = "ALB type (application or network)"
  type        = string
  default     = "application"
  validation {
    condition     = contains(["application", "network"], var.eks_alb_type)
    error_message = "ALB type must be either 'application' or 'network'."
  }
}

variable "eks_alb_target_groups" {
  description = "Map of ALB target groups"
  type = map(object({
    port                  = number
    protocol              = string
    target_type           = optional(string, "ip")
    health_check_path     = optional(string, "/health")
    health_check_port     = optional(string, "traffic-port")
    health_check_protocol = optional(string, "HTTP")
    health_check_matcher  = optional(string, "200")
    health_check_interval = optional(number, 30)
    health_check_timeout  = optional(number, 5)
    healthy_threshold     = optional(number, 2)
    unhealthy_threshold   = optional(number, 2)
    deregistration_delay  = optional(number, 300)
    stickiness = optional(object({
      enabled = bool
      type    = string
    }), null)
  }))
  default = {
    web = {
      port                  = 80
      protocol              = "HTTP"
      target_type           = "ip"
      health_check_path     = "/health"
      health_check_port     = "traffic-port"
      health_check_protocol = "HTTP"
      health_check_matcher  = "200"
      health_check_interval = 30
      health_check_timeout  = 5
      healthy_threshold     = 2
      unhealthy_threshold   = 2
      deregistration_delay  = 300
      stickiness = {
        enabled = false
        type    = "lb_cookie"
      }
    }
  }
}

variable "eks_alb_listeners" {
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

variable "eks_allowed_cidrs" {
  description = "CIDR blocks allowed to access ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "eks_enable_waf" {
  description = "Enable AWS WAF for ALB"
  type        = bool
  default     = false
}

variable "eks_waf_web_acl_arn" {
  description = "ARN of WAF Web ACL to associate with ALB"
  type        = string
  default     = null
}

variable "eks_tags" {
  description = "Additional tags for EKS resources"
  type        = map(string)
  default     = {}
}

# VPN Configuration
variable "vpn_enable" {
  description = "Enable VPN server deployment"
  type        = bool
  default     = true
}

variable "vpn_instance_type" {
  description = "EC2 instance type for VPN server"
  type        = string
  default     = "t3a.micro"
}

variable "vpn_volume_size" {
  description = "Root volume size in GB for VPN server"
  type        = number
  default     = 20
}

variable "vpn_allowed_ssh_cidrs" {
  description = "List of CIDR blocks allowed to SSH to the VPN server"
  type        = list(string)
  default     = []
}

variable "vpn_public_ssh_key" {
  description = "Public SSH key for VPN server access"
  type        = string
  default     = ""
}

variable "vpn_client_name" {
  description = "Name for the VPN client user"
  type        = string
  default     = "vpn-client"
}

variable "vpn_tags" {
  description = "Additional tags for VPN resources"
  type        = map(string)
  default     = {}
}

# External DNS Configuration
variable "eks_enable_external_dns" {
  description = "Enable External DNS for automatic DNS management"
  type        = bool
  default     = true
}

variable "eks_external_dns_version" {
  description = "External DNS version to deploy"
  type        = string
  default     = "1.13.1"
}

variable "eks_external_dns_domain_filters" {
  description = "List of domains to filter DNS records"
  type        = list(string)
  default     = []
}

variable "eks_external_dns_zone_type" {
  description = "Type of DNS zone (public or private)"
  type        = string
  default     = "public"
}

variable "eks_external_dns_policy" {
  description = "External DNS policy (sync, upsert-only, create-only)"
  type        = string
  default     = "upsert-only"
}

variable "eks_external_dns_txt_owner_id" {
  description = "TXT record owner ID for External DNS"
  type        = string
  default     = ""
}

variable "eks_external_dns_txt_prefix" {
  description = "TXT record prefix for External DNS"
  type        = string
  default     = "external-dns"
}

variable "eks_external_dns_annotation_filter" {
  description = "Annotation filter for External DNS"
  type        = string
  default     = "external-dns.alpha.kubernetes.io/hostname"
}

variable "eks_external_dns_label_filter" {
  description = "Label filter for External DNS"
  type        = string
  default     = ""
}

# Route53 Configuration
variable "route53_enable" {
  description = "Enable Route53 hosted zones"
  type        = bool
  default     = true
}

variable "route53_hosted_zones" {
  description = "Map of Route53 hosted zones to create"
  type = map(object({
    domain_name = string
    comment     = optional(string, "")
  }))
  default = {}
}

variable "route53_dns_records" {
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

variable "route53_health_checks" {
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

variable "route53_tags" {
  description = "Additional tags for Route53 resources"
  type        = map(string)
  default     = {}
}

# Security Configuration
variable "security_enable" {
  description = "Enable advanced security controls"
  type        = bool
  default     = true
}

variable "security_domain_name" {
  description = "Domain name for SSL certificate"
  type        = string
  default     = "example.com"
}

variable "security_subject_alternative_names" {
  description = "Subject alternative names for SSL certificate"
  type        = list(string)
  default     = ["*.example.com"]
}

variable "security_tags" {
  description = "Additional tags for security resources"
  type        = map(string)
  default     = {}
}

# Developer Access Configuration
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

variable "developer_allowed_ip_ranges" {
  description = "List of IP ranges allowed for developer access"
  type        = list(string)
  default     = ["202.131.107.130/32", "202.131.110.138/32"]
}
