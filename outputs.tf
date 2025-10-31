output "instance_id" {
  description = "ID of the EC2 instance"
  value       = module.ec2_instance.instance_id
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = module.ec2_instance.instance_public_ip
}

output "elastic_ip" {
  description = "Elastic IP address of the EC2 instance"
  value       = module.ec2_instance.elastic_ip
}

output "security_group_id" {
  description = "ID of the security group"
  value       = module.ec2_instance.security_group_id
}

output "key_pair_name" {
  description = "Name of the primary key pair"
  value       = module.ec2_instance.key_name
}

output "all_key_pair_names" {
  description = "Names of all key pairs"
  value       = module.ec2_instance.all_key_names
}

output "ssh_private_key_secret_arn" {
  description = "ARN of the secret containing the SSH private key (only if generated)"
  value       = length(var.public_ssh_keys) == 0 ? aws_secretsmanager_secret.ssh_private_key[0].arn : null
  sensitive   = true
}

output "ssh_connection_command" {
  description = "SSH connection command"
  value       = "ssh -i <private_key_file> ubuntu@${module.ec2_instance.elastic_ip}"
}

# Jenkins Outputs
output "jenkins_url" {
  description = "Jenkins URL via NGINX reverse proxy"
  value       = module.ec2_instance.jenkins_url
}

output "jenkins_direct_url" {
  description = "Jenkins direct URL (port 8080)"
  value       = module.ec2_instance.jenkins_direct_url
}

output "jenkins_setup_status" {
  description = "Jenkins setup completion status"
  value       = module.ec2_instance.jenkins_setup_complete
}

# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

# NAT Gateway Outputs
output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways"
  value       = module.vpc.nat_gateway_ids
}

output "nat_gateway_public_ips" {
  description = "Public IPs of the NAT Gateways"
  value       = module.vpc.nat_gateway_public_ips
}

output "nat_gateway_count" {
  description = "Number of NAT Gateways deployed"
  value       = length(module.vpc.nat_gateway_ids)
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.vpc.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.vpc.private_subnet_ids
}

# S3 Outputs
output "s3_bucket_ids" {
  description = "IDs of the S3 buckets"
  value       = module.s3_storage.bucket_ids
}

output "s3_bucket_arns" {
  description = "ARNs of the S3 buckets"
  value       = module.s3_storage.bucket_arns
}

output "s3_bucket_domain_names" {
  description = "Domain names of the S3 buckets"
  value       = module.s3_storage.bucket_domain_names
}

output "cloudfront_domain_names" {
  description = "Domain names of the CloudFront distributions"
  value       = module.s3_storage.cloudfront_domain_names
}

output "cloudfront_urls" {
  description = "URLs of the CloudFront distributions"
  value       = module.s3_storage.cloudfront_urls
}

output "s3_instance_profile_name" {
  description = "Name of the IAM instance profile for S3 access"
  value       = module.s3_storage.instance_profile_name
}

# Legacy S3 outputs for backward compatibility
output "s3_bucket_id" {
  description = "ID of the first S3 bucket (legacy)"
  value       = module.s3_storage.bucket_id
}

output "s3_bucket_arn" {
  description = "ARN of the first S3 bucket (legacy)"
  value       = module.s3_storage.bucket_arn
}

output "cloudfront_domain_name" {
  description = "Domain name of the first CloudFront distribution (legacy)"
  value       = module.s3_storage.cloudfront_domain_name
}

output "cloudfront_url" {
  description = "URL of the first CloudFront distribution (legacy)"
  value       = module.s3_storage.cloudfront_url
}

# Aurora Outputs
output "aurora_cluster_id" {
  description = "ID of the Aurora cluster"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].cluster_id : module.aurora_mysql[0].cluster_id
}

output "aurora_cluster_endpoint" {
  description = "Endpoint of the Aurora cluster"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].cluster_endpoint : module.aurora_mysql[0].cluster_endpoint
}

output "aurora_cluster_reader_endpoint" {
  description = "Reader endpoint of the Aurora cluster"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].cluster_reader_endpoint : module.aurora_mysql[0].cluster_reader_endpoint
}

output "aurora_cluster_port" {
  description = "Port of the Aurora cluster"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].cluster_port : module.aurora_mysql[0].cluster_port
}

output "aurora_database_name" {
  description = "Name of the Aurora database"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].cluster_database_name : module.aurora_mysql[0].cluster_database_name
}

output "aurora_credentials_secret_arn" {
  description = "ARN of the secret containing Aurora credentials"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].credentials_secret_arn : module.aurora_mysql[0].credentials_secret_arn
  sensitive   = true
}

output "aurora_connection_command" {
  description = "Database connection command (MySQL or PostgreSQL)"
  value       = var.aurora_use_postgresql ? module.aurora_postgresql[0].connection_command : module.aurora_mysql[0].connection_command
  sensitive   = true
}

# ECR Outputs
output "ecr_repository_urls" {
  description = "URLs of the ECR repositories"
  value       = module.ecr_repositories.repository_urls
}

output "ecr_repository_arns" {
  description = "ARNs of the ECR repositories"
  value       = module.ecr_repositories.repository_arns
}

output "ecr_repository_names" {
  description = "Names of the ECR repositories"
  value       = module.ecr_repositories.repository_names
}

output "ecr_login_command" {
  description = "AWS CLI command to login to ECR"
  value       = module.ecr_repositories.login_command
}

output "ecr_docker_commands" {
  description = "Docker commands for each repository"
  value       = module.ecr_repositories.docker_push_commands
}

# EKS Outputs
output "eks_cluster_id" {
  description = "ID of the EKS cluster"
  value       = module.eks_cluster.cluster_id
}

output "eks_cluster_arn" {
  description = "ARN of the EKS cluster"
  value       = module.eks_cluster.cluster_arn
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks_cluster.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks_cluster.cluster_endpoint
}

output "eks_cluster_version" {
  description = "Kubernetes version of the EKS cluster"
  value       = module.eks_cluster.cluster_version
}

output "eks_cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks_cluster.cluster_security_group_id
}

output "eks_cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks_cluster.cluster_certificate_authority_data
}

output "eks_cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = module.eks_cluster.cluster_oidc_issuer_url
}

output "eks_cluster_oidc_provider_arn" {
  description = "ARN of the OIDC provider"
  value       = module.eks_cluster.cluster_oidc_provider_arn
}

output "eks_node_groups" {
  description = "Map of EKS node groups"
  value       = module.eks_cluster.node_groups
}

output "eks_node_group_arns" {
  description = "ARNs of the EKS node groups"
  value       = module.eks_cluster.node_group_arns
}

output "eks_cluster_iam_role_arn" {
  description = "ARN of the EKS cluster IAM role"
  value       = module.eks_cluster.cluster_iam_role_arn
}

output "eks_node_group_iam_role_arn" {
  description = "ARN of the EKS node group IAM role"
  value       = module.eks_cluster.node_group_iam_role_arn
}

output "eks_aws_load_balancer_controller_role_arn" {
  description = "ARN of the AWS Load Balancer Controller IAM role"
  value       = module.eks_cluster.aws_load_balancer_controller_role_arn
}

output "eks_alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = module.eks_cluster.alb_arn
}

output "eks_alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.eks_cluster.alb_dns_name
}

output "eks_alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = module.eks_cluster.alb_zone_id
}

output "eks_alb_hosted_zone_id" {
  description = "Hosted zone ID of the Application Load Balancer"
  value       = module.eks_cluster.alb_hosted_zone_id
}

output "eks_alb_security_group_id" {
  description = "Security group ID of the Application Load Balancer"
  value       = module.eks_cluster.alb_security_group_id
}

output "eks_target_groups" {
  description = "Map of ALB target groups"
  value       = module.eks_cluster.target_groups
}

output "eks_target_group_arns" {
  description = "ARNs of the ALB target groups"
  value       = module.eks_cluster.target_group_arns
}

output "eks_listeners" {
  description = "Map of ALB listeners"
  value       = module.eks_cluster.listeners
}

output "eks_listener_arns" {
  description = "ARNs of the ALB listeners"
  value       = module.eks_cluster.listener_arns
}

output "eks_addons" {
  description = "Map of EKS add-ons"
  value       = module.eks_cluster.addons
}

output "eks_kubectl_config_command" {
  description = "Command to configure kubectl for the EKS cluster"
  value       = module.eks_cluster.kubectl_config_command
}

output "eks_kubectl_config_file" {
  description = "Path to the kubectl config file"
  value       = module.eks_cluster.kubectl_config_file
}

output "eks_cluster_access_commands" {
  description = "Commands to access the EKS cluster"
  value       = module.eks_cluster.cluster_access_commands
}

output "eks_alb_access_info" {
  description = "ALB access information"
  value       = module.eks_cluster.alb_access_info
}

output "eks_waf_web_acl_association_id" {
  description = "ID of the WAF Web ACL association with ALB"
  value       = module.eks_cluster.waf_web_acl_association_id
}

output "eks_cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for EKS cluster"
  value       = module.eks_cluster.cloudwatch_log_group_name
}

output "eks_cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for EKS cluster"
  value       = module.eks_cluster.cloudwatch_log_group_arn
}


# External DNS Outputs
output "external_dns_iam_role_arn" {
  description = "ARN of the External DNS IAM role"
  value       = module.eks_cluster.external_dns_iam_role_arn
}

output "external_dns_helm_release_name" {
  description = "Name of the External DNS Helm release"
  value       = module.eks_cluster.external_dns_helm_release_name
}

output "external_dns_helm_release_version" {
  description = "Version of the External DNS Helm release"
  value       = module.eks_cluster.external_dns_helm_release_version
}

output "external_dns_helm_release_namespace" {
  description = "Namespace of the External DNS Helm release"
  value       = module.eks_cluster.external_dns_helm_release_namespace
}

output "external_dns_commands" {
  description = "Commands to manage External DNS"
  value       = module.eks_cluster.external_dns_commands
}

# VPN Outputs
output "vpn_instance_id" {
  description = "ID of the VPN EC2 instance"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_instance_id : null
}

output "vpn_instance_public_ip" {
  description = "Public IP of the VPN EC2 instance"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_instance_public_ip : null
}

output "vpn_elastic_ip" {
  description = "Elastic IP address of the VPN server"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_elastic_ip : null
}

output "vpn_elastic_ip_dns" {
  description = "Elastic IP DNS name"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_elastic_ip_dns : null
}

output "vpn_security_group_id" {
  description = "Security group ID of the VPN server"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_security_group_id : null
}

output "vpn_key_pair_name" {
  description = "Key pair name for VPN server"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_key_pair_name : null
}

output "vpn_ssh_private_key_secret_arn" {
  description = "ARN of the secret containing the VPN server private key"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_ssh_private_key_secret_arn : null
}

output "vpn_password_secret_arn" {
  description = "ARN of the secret containing the OpenVPN password"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_password_secret_arn : null
}

output "vpn_connection_secret_arn" {
  description = "ARN of the secret containing VPN connection details"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_connection_secret_arn : null
}

output "vpn_admin_url" {
  description = "OpenVPN Access Server admin URL"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_admin_url : null
}

output "vpn_client_url" {
  description = "OpenVPN Access Server client URL"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_client_url : null
}

output "vpn_ssh_connection_command" {
  description = "SSH connection command for VPN server"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_ssh_connection_command : null
}

output "vpn_connection_info" {
  description = "VPN connection information"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_connection_info : null
}

output "vpn_cloudwatch_log_group" {
  description = "CloudWatch log group for VPN server"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_cloudwatch_log_group : null
}

output "vpn_cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN for VPN server"
  value       = var.vpn_enable ? module.vpn_server[0].vpn_cloudwatch_log_group_arn : null
}

# Route53 Outputs
output "route53_hosted_zone_ids" {
  description = "Map of hosted zone IDs"
  value       = var.route53_enable ? module.route53[0].hosted_zone_ids : {}
}

output "route53_hosted_zone_names" {
  description = "Map of hosted zone names"
  value       = var.route53_enable ? module.route53[0].hosted_zone_names : {}
}

output "route53_hosted_zone_name_servers" {
  description = "Map of hosted zone name servers"
  value       = var.route53_enable ? module.route53[0].hosted_zone_name_servers : {}
}

output "route53_hosted_zone_arns" {
  description = "Map of hosted zone ARNs"
  value       = var.route53_enable ? module.route53[0].hosted_zone_arns : {}
}

output "route53_dns_record_ids" {
  description = "Map of DNS record IDs"
  value       = var.route53_enable ? module.route53[0].dns_record_ids : {}
}

output "route53_health_check_ids" {
  description = "Map of health check IDs"
  value       = var.route53_enable ? module.route53[0].health_check_ids : {}
}

output "route53_health_check_arns" {
  description = "Map of health check ARNs"
  value       = var.route53_enable ? module.route53[0].health_check_arns : {}
}

output "route53_name_servers" {
  description = "Name servers for all hosted zones"
  value       = var.route53_enable ? module.route53[0].name_servers : {}
}

output "route53_dns_commands" {
  description = "Commands to manage DNS"
  value       = var.route53_enable ? module.route53[0].dns_commands : null
}


# Security Outputs
output "security_cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = var.security_enable ? module.security[0].cloudtrail_arn : null
}

output "security_guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.security_enable ? module.security[0].guardduty_detector_id : null
}

output "security_security_hub_arn" {
  description = "ARN of the Security Hub"
  value       = var.security_enable ? module.security[0].security_hub_arn : null
}

output "security_config_recorder_name" {
  description = "Name of the Config recorder"
  value       = var.security_enable ? module.security[0].config_recorder_name : null
}

output "security_waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = var.security_enable ? module.security[0].waf_web_acl_arn : null
}

output "security_acm_certificate_arn" {
  description = "ARN of the ACM certificate"
  value       = var.security_enable ? module.security[0].acm_certificate_arn : null
}

output "security_vpc_flow_log_id" {
  description = "ID of the VPC flow log"
  value       = var.security_enable ? module.security[0].vpc_flow_log_id : null
}

output "security_commands" {
  description = "Commands to manage security services"
  value       = var.security_enable ? module.security[0].security_commands : null
}
