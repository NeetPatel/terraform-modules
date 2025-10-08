provider "aws" {
  region = var.aws_region
}

# Store EC2 private key in AWS Secrets Manager (only if using generated key)
resource "aws_secretsmanager_secret" "ssh_private_key" {
  count                   = length(var.public_ssh_keys) == 0 ? 1 : 0
  name                    = "${var.project_name}-ec2-ssh-private-key"
  description             = "Private key for EC2 instance SSH access"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "ssh_private_key" {
  count         = length(var.public_ssh_keys) == 0 ? 1 : 0
  secret_id     = aws_secretsmanager_secret.ssh_private_key[0].id
  secret_string = module.ec2_instance.private_key
}

# Call the VPC module
module "vpc" {
  source = "./modules/vpc"

  project_name = var.project_name
  aws_region   = var.aws_region
  environment  = var.environment

  # VPC Configuration
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  enable_nat_gateway   = var.enable_nat_gateway
}

# Call the EC2 module
module "ec2_instance" {
  source = "./modules/ec2"

  project_name = var.project_name
  aws_region   = var.aws_region
  environment  = var.environment

  # VPC Configuration
  vpc_id    = module.vpc.vpc_id
  subnet_id = module.vpc.public_subnet_ids[0]

  # Security group configuration
  allowed_ssh_cidrs       = var.allowed_ssh_cidrs
  privileged_access_cidrs = var.privileged_access_cidrs

  # SSH Key configuration
  public_ssh_keys = var.public_ssh_keys

  # Instance configuration
  instance_type = var.instance_type
  ami_id        = var.ami_id
}

# Call the S3 module
module "s3_storage" {
  source = "./modules/s3"

  project_name = var.project_name
  environment  = var.environment

  # S3 Configuration
  bucket_name         = var.s3_bucket_name
  buckets             = var.s3_buckets
  bucket_names        = var.s3_bucket_names
  environment_buckets = var.s3_environment_buckets
  enable_versioning   = var.s3_enable_versioning
  block_public_access = var.s3_block_public_access
  default_root_object = var.s3_default_root_object
  price_class         = var.s3_price_class
}

# Call the Aurora module
module "aurora_mysql" {
  source = "./modules/aurora"

  project_name = var.project_name
  environment  = var.environment

  # VPC Configuration
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  ec2_security_group_id = module.ec2_instance.security_group_id

  # Aurora Configuration
  database_name           = var.aurora_database_name
  master_username         = var.aurora_master_username
  engine_version          = var.aurora_engine_version
  instance_class          = var.aurora_instance_class
  instance_count          = var.aurora_instance_count
  max_capacity            = var.aurora_max_capacity
  min_capacity            = var.aurora_min_capacity
  backup_retention_period = var.aurora_backup_retention_period
  deletion_protection     = var.aurora_deletion_protection
  skip_final_snapshot     = var.aurora_skip_final_snapshot
}

# Call the ECR module
module "ecr_repositories" {
  source = "./modules/ecr"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  # ECR Configuration
  repositories             = var.ecr_repositories
  ecr_repository_names     = var.ecr_repository_names
  enable_lifecycle_policy  = var.ecr_enable_lifecycle_policy
  default_lifecycle_policy = var.ecr_default_lifecycle_policy
}

# Call the EKS module
module "eks_cluster" {
  source = "./modules/eks"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  # VPC Configuration
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  public_subnet_ids  = module.vpc.public_subnet_ids

  # EKS Configuration
  cluster_name                         = var.eks_cluster_name
  cluster_version                      = var.eks_cluster_version
  cluster_endpoint_private_access      = var.eks_cluster_endpoint_private_access
  cluster_endpoint_public_access       = var.eks_cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs = var.eks_cluster_endpoint_public_access_cidrs
  cluster_enabled_log_types            = var.eks_cluster_enabled_log_types
  cluster_encryption_config            = var.eks_cluster_encryption_config

  # Node Group Configuration
  node_groups = var.eks_node_groups

  # ALB Configuration
  enable_alb        = var.eks_enable_alb
  alb_name          = var.eks_alb_name
  alb_scheme        = var.eks_alb_scheme
  alb_type          = var.eks_alb_type
  alb_target_groups = var.eks_alb_target_groups
  alb_listeners     = var.eks_alb_listeners

  # Security Configuration
  allowed_cidrs       = var.eks_allowed_cidrs
  enable_waf          = var.eks_enable_waf
  waf_web_acl_arn     = var.eks_enable_waf && var.security_enable ? module.security[0].waf_web_acl_arn : var.eks_waf_web_acl_arn
  ssl_certificate_arn = var.security_enable ? module.security[0].acm_certificate_arn : null

  # Karpenter Configuration
  enable_karpenter    = var.eks_enable_karpenter
  karpenter_version   = var.eks_karpenter_version
  karpenter_nodepools = var.eks_karpenter_nodepools

  # External DNS Configuration
  enable_external_dns            = var.eks_enable_external_dns
  external_dns_version           = var.eks_external_dns_version
  external_dns_domain_filters    = var.eks_external_dns_domain_filters
  external_dns_zone_type         = var.eks_external_dns_zone_type
  external_dns_policy            = var.eks_external_dns_policy
  external_dns_txt_owner_id      = var.eks_external_dns_txt_owner_id
  external_dns_txt_prefix        = var.eks_external_dns_txt_prefix
  external_dns_annotation_filter = var.eks_external_dns_annotation_filter
  external_dns_label_filter      = var.eks_external_dns_label_filter

  # Tags
  tags = var.eks_tags
}

# VPN Server
module "vpn_server" {
  count = var.vpn_enable ? 1 : 0

  source = "./modules/vpn-ec2"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  # VPC Configuration
  vpc_id    = module.vpc.vpc_id
  subnet_id = module.vpc.public_subnet_ids[0]

  # Instance Configuration
  ami_id        = var.ami_id
  instance_type = var.vpn_instance_type
  volume_size   = var.vpn_volume_size

  # Security Configuration
  allowed_ssh_cidrs = var.vpn_allowed_ssh_cidrs
  public_ssh_key    = var.vpn_public_ssh_key != "" ? var.vpn_public_ssh_key : var.public_ssh_keys[0]

  # VPN Configuration
  vpn_client_name = var.vpn_client_name

  # Tags
  tags = var.vpn_tags
}

# Route53 Hosted Zones
module "route53" {
  count = var.route53_enable ? 1 : 0

  source = "./modules/route53"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  # Route53 Configuration
  hosted_zones  = var.route53_hosted_zones
  dns_records   = var.route53_dns_records
  health_checks = var.route53_health_checks

  # Tags
  tags = var.route53_tags
}

# Advanced Security Controls
module "security" {
  count = var.security_enable ? 1 : 0

  source = "./modules/security"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  # VPC Configuration
  vpc_id = module.vpc.vpc_id

  # SSL Certificate Configuration
  domain_name               = var.security_domain_name
  subject_alternative_names = var.security_subject_alternative_names

  # Tags
  tags = var.security_tags
}
