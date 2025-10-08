# DevOps Infrastructure with Terraform

This Terraform configuration provisions a comprehensive AWS infrastructure including EC2 instances, VPC, S3 buckets with CloudFront CDN, Aurora MySQL Serverless database, ECR repositories, EKS cluster with Karpenter autoscaler, Route53 DNS management, and External DNS integration with best security practices and modular design.

## 🏗️ Architecture

- **EC2 Instance**: Ubuntu 22.04 LTS with security hardening and Elastic IP
- **VPC**: Custom VPC with public/private subnets, NAT Gateway, and Internet Gateway
- **S3 Storage**: Multiple S3 buckets with CloudFront CDN distributions
- **Aurora Database**: MySQL Serverless v2 with automatic scaling and encryption
- **ECR Repositories**: Multiple container registries with lifecycle policies
- **EKS Cluster**: Kubernetes cluster with Karpenter autoscaler and ALB
- **Route53 DNS**: Hosted zones for domain management and DNS records
- **External DNS**: Automatic DNS record management for Kubernetes services
- **Security Groups**: Restrictive inbound rules (HTTP open, SSH restricted)
- **Key Management**: SSH key pairs with private keys stored in AWS Secrets Manager
- **Encryption**: Encrypted storage and database
- **Monitoring**: CloudWatch monitoring enabled

## 🔒 Security Features

### Network Security
- **HTTP (port 80)**: Open to all IPs for web traffic
- **HTTPS (port 443)**: Open to all IPs for secure web traffic
- **SSH (port 22)**: Restricted to specific IP addresses only
- **Outbound**: All outbound traffic allowed

### Instance Security
- **Encrypted Root Volume**: GP3 encrypted storage
- **Key-based SSH**: Password authentication disabled
- **Root Login Disabled**: SSH root access prohibited
- **CloudWatch Monitoring**: Detailed monitoring enabled

### Key Management
- **SSH Key Pair**: 4096-bit RSA key pair generated
- **Secure Storage**: Private key stored in AWS Secrets Manager
- **Recovery Window**: 7-day recovery window for accidental deletion

## 📁 Project Structure

```
.
├── main.tf                    # Main Terraform configuration
├── variables.tf               # Input variables
├── outputs.tf                 # Output values
├── versions.tf                # Provider version constraints
├── terraform.tfvars           # Variables file
├── terraform.tfvars.example   # Example variables file
├── README.md                  # This file
└── modules/
    ├── ec2/                   # EC2 instance module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── vpc/                   # VPC network module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── s3/                    # S3 storage module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── aurora/                # Aurora database module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── ecr/                   # ECR repositories module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── eks/                   # EKS cluster module
    │   ├── main.tf
    │   ├── variables.tf
    │   ├── outputs.tf
    │   ├── versions.tf
    │   └── karpenter-userdata.sh
    ├── vpn-ec2/               # VPN EC2 instance module
    │   ├── main.tf
    │   ├── variables.tf
    │   ├── outputs.tf
    │   └── vpn-userdata.sh
    └── route53/               # Route53 DNS module
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

## 🚀 Quick Start

### Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform installed** (version >= 1.0)
3. **AWS permissions** for EC2, Secrets Manager, and VPC

### Required AWS Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "secretsmanager:*",
                "iam:*",
                "s3:*",
                "cloudfront:*",
                "rds:*",
                "ecr:*",
                "eks:*",
                "route53:*",
                "sqs:*",
                "events:*",
                "logs:*"
            ],
            "Resource": "*"
        }
    ]
}
```

### Deployment Steps

1. **Clone and navigate to the directory**:
   ```bash
   cd /path/to/terrform
   ```

2. **Configure variables**:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your specific values
   ```

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

4. **Review the plan**:
   ```bash
   terraform plan
   ```

5. **Deploy the infrastructure**:
   ```bash
   terraform apply
   ```

6. **Get SSH access**:
   ```bash
   # Retrieve the private key from Secrets Manager
   aws secretsmanager get-secret-value \
     --secret-id "devops-test-pre-prod-ec2-ssh-private-key" \
     --query SecretString --output text > private_key.pem
   
   # Set proper permissions
   chmod 600 private_key.pem
   
   # Connect to the instance
   ssh -i private_key.pem ubuntu@<ELASTIC_IP>
   ```

7. **Access Aurora Database**:
   ```bash
   # Get database credentials from Secrets Manager
   aws secretsmanager get-secret-value \
     --secret-id "devops-test-pre-prod-aurora-credentials" \
     --query SecretString --output text
   
   # Connect to Aurora (from EC2 instance)
   mysql -h <aurora-endpoint> -u admin -p
   ```

8. **Push to ECR**:
   ```bash
   # Login to ECR
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com
   
   # Tag and push image
   docker tag myapp:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/devops-test-pre-prod-api:latest
   docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/devops-test-pre-prod-api:latest
   ```

9. **Configure EKS Access**:
   ```bash
   # Configure kubectl
   aws eks update-kubeconfig --region us-east-1 --name devops-test-pre-prod-eks
   
   # Verify cluster access
   kubectl get nodes
   
   # Check Karpenter status
   kubectl get pods -n karpenter
   
   # Check NodePools
   kubectl get nodepools
   ```

10. **Deploy Applications to EKS**:
    ```bash
    # Create a sample deployment
    kubectl create deployment nginx --image=nginx
    
    # Scale the deployment
    kubectl scale deployment nginx --replicas=5
    
    # Watch Karpenter provision nodes
    kubectl get nodes -w
    ```

## ⚙️ Configuration

### Core Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `aws_region` | AWS region for resources | `us-east-1` | No |
| `project_name` | Project name for resource naming | `devops-test` | No |
| `environment` | Environment name | `pre-prod` | No |
| `ami_id` | AMI ID for EC2 instance | None | **Yes** |
| `allowed_ssh_cidrs` | CIDR blocks for SSH access | None | **Yes** |

### EC2 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `instance_type` | EC2 instance type | `t3.small` |
| `public_ssh_keys` | List of public SSH keys | `[]` |
| `privileged_access_cidrs` | Additional privileged access CIDRs | `[]` |

### VPC Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `vpc_cidr` | CIDR block for VPC | `10.0.0.0/16` |
| `public_subnet_cidrs` | Public subnet CIDRs | `["10.0.1.0/24", "10.0.2.0/24"]` |
| `private_subnet_cidrs` | Private subnet CIDRs | `["10.0.10.0/24", "10.0.20.0/24"]` |
| `enable_nat_gateway` | Enable NAT Gateway | `true` |

### S3 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `s3_environment_buckets` | Environment-specific bucket configurations | `{}` |
| `s3_bucket_names` | Simple list of bucket names | `[]` |
| `s3_buckets` | Advanced bucket configurations | `[]` |

### Aurora Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `aurora_database_name` | Database name | `devopsdb` |
| `aurora_master_username` | Master username | `admin` |
| `aurora_engine_version` | Aurora MySQL version | `8.0.mysql_aurora.3.02.0` |
| `aurora_instance_class` | Instance class | `db.serverless` |
| `aurora_max_capacity` | Max serverless capacity | `8` |
| `aurora_min_capacity` | Min serverless capacity | `0.5` |

### ECR Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `ecr_repository_names` | Simple list of repository names | `[]` |
| `ecr_repositories` | Advanced repository configurations | `[]` |
| `ecr_enable_lifecycle_policy` | Enable default lifecycle policy | `true` |

### EKS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `eks_cluster_name` | Name of the EKS cluster | `""` |
| `eks_cluster_version` | Kubernetes version | `"1.32"` |
| `eks_cluster_endpoint_private_access` | Enable private API access | `true` |
| `eks_cluster_endpoint_public_access` | Enable public API access | `true` |
| `eks_cluster_endpoint_public_access_cidrs` | CIDRs for public API access | `["0.0.0.0/0"]` |
| `eks_cluster_enabled_log_types` | EKS control plane logs | `["api", "audit", "authenticator", "controllerManager", "scheduler"]` |
| `eks_cluster_encryption_config` | EKS encryption configuration | `null` |

### EKS Node Groups

| Variable | Description | Default |
|----------|-------------|---------|
| `eks_node_groups` | Map of EKS node groups | `{}` |
| `eks_enable_alb` | Enable Application Load Balancer | `true` |
| `eks_alb_name` | ALB name | `""` |
| `eks_alb_scheme` | ALB scheme (internet-facing/internal) | `"internet-facing"` |
| `eks_alb_type` | ALB type (application/network) | `"application"` |
| `eks_alb_target_groups` | ALB target groups | `{}` |
| `eks_alb_listeners` | ALB listeners | `{}` |

### Karpenter Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `eks_enable_karpenter` | Enable Karpenter autoscaler | `true` |
| `eks_karpenter_version` | Karpenter version | `"0.37.0"` |
| `eks_karpenter_nodepools` | Map of Karpenter NodePools | `{}` |

### External DNS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `eks_enable_external_dns` | Enable External DNS | `true` |
| `eks_external_dns_version` | External DNS version | `"1.13.1"` |
| `eks_external_dns_domain_filters` | Domain filters for DNS records | `[]` |
| `eks_external_dns_zone_type` | DNS zone type (public/private) | `"public"` |
| `eks_external_dns_policy` | External DNS policy | `"upsert-only"` |

### Route53 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `route53_enable` | Enable Route53 hosted zones | `true` |
| `route53_hosted_zones` | Map of hosted zones to create | `{}` |
| `route53_dns_records` | Map of DNS records to create | `{}` |
| `route53_health_checks` | Map of health checks to create | `{}` |

### Example Configuration

```hcl
# terraform.tfvars
aws_region = "us-east-1"
project_name = "devops-test"
environment = "pre-prod"
instance_type = "t3.small"

# REQUIRED: Specific AMI ID
ami_id = "ami-07a3add10195338ad"

# REQUIRED: Replace with your actual IP addresses
allowed_ssh_cidrs = [
  "<YOUR_IP>",
  "<YOUR_IP>"
]

# SSH Keys
public_ssh_keys = [
  "<public_ssh_key>"
]

# VPC Configuration
vpc_cidr = "10.0.0.0/16"
public_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]
private_subnet_cidrs = ["10.0.10.0/24", "10.0.20.0/24"]
enable_nat_gateway = true

# S3 Configuration - Environment-Specific Buckets
s3_environment_buckets = {
  "dev" = {
    bucket_names = [
      "static-assets",
      "uploads"
    ]
    enable_cloudfront = true
    enable_versioning = true
    block_public_access = true
  }
}

# Aurora Configuration
aurora_database_name = "devopsdb"
aurora_master_username = "admin"
aurora_engine_version = "8.0.mysql_aurora.3.02.0"
aurora_instance_class = "db.serverless"
aurora_max_capacity = 8
aurora_min_capacity = 0.5

# ECR Configuration
ecr_repository_names = [
  "api",
  "worker", 
  "backend",
  "frontend"
]

# EKS Configuration
eks_cluster_name = ""
eks_cluster_version = "1.32"
eks_cluster_endpoint_private_access = true
eks_cluster_endpoint_public_access = true
eks_cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
eks_cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

eks_node_groups = {
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

eks_enable_alb = true
eks_alb_name = ""
eks_alb_scheme = "internet-facing"
eks_alb_type = "application"

eks_alb_target_groups = {
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

eks_alb_listeners = {
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

eks_allowed_cidrs = ["0.0.0.0/0"]
eks_enable_waf = false
eks_waf_web_acl_arn = null
eks_tags = {}

# Karpenter Configuration
eks_enable_karpenter = true
eks_karpenter_version = "0.37.0"

eks_karpenter_nodepools = {
  default = {
    instance_types = ["t3.medium", "t3.large", "t3.xlarge"]
    capacity_type  = "spot"
    min_capacity   = 0
    max_capacity   = 100
    ttl_seconds_after_empty = 30
    ttl_seconds_until_expired = 2592000
    labels = {
      Environment = "pre-prod"
      NodeType    = "karpenter"
    }
    taints = []
    requirements = [
      {
        key      = "kubernetes.io/arch"
        operator = "In"
        values   = ["amd64"]
      },
      {
        key      = "karpenter.sh/capacity-type"
        operator = "In"
        values   = ["spot"]
      }
    ]
  }
}

# External DNS Configuration
eks_enable_external_dns = true
eks_external_dns_version = "1.13.1"
eks_external_dns_domain_filters = []
eks_external_dns_zone_type = "public"
eks_external_dns_policy = "upsert-only"

# Route53 Configuration
route53_enable = true

route53_hosted_zones = {
  "main-domain" = {
    domain_name = "example.com"
    comment     = "Main domain for devops-test pre-prod environment"
  }
}
```

## 🔍 Outputs

After deployment, Terraform will output:

### EC2 Outputs
- `instance_id`: EC2 instance ID
- `instance_public_ip`: Instance public IP
- `elastic_ip`: Elastic IP address
- `security_group_id`: Security group ID
- `key_pair_name`: AWS key pair name
- `ssh_private_key_secret_arn`: ARN of the secret containing the private key
- `ssh_connection_command`: SSH connection command

### VPC Outputs
- `vpc_id`: VPC ID
- `public_subnet_ids`: Public subnet IDs
- `private_subnet_ids`: Private subnet IDs
- `internet_gateway_id`: Internet Gateway ID
- `nat_gateway_id`: NAT Gateway ID

### S3 Outputs
- `s3_bucket_ids`: S3 bucket IDs
- `s3_bucket_arns`: S3 bucket ARNs
- `cloudfront_domain_names`: CloudFront distribution domain names
- `cloudfront_urls`: CloudFront distribution URLs
- `s3_instance_profile_name`: IAM instance profile name

### Aurora Outputs
- `aurora_cluster_id`: Aurora cluster ID
- `aurora_cluster_endpoint`: Aurora cluster endpoint
- `aurora_cluster_reader_endpoint`: Aurora reader endpoint
- `aurora_credentials_secret_arn`: ARN of the secret containing Aurora credentials
- `aurora_connection_command`: MySQL connection command

### ECR Outputs
- `ecr_repository_urls`: ECR repository URLs
- `ecr_repository_arns`: ECR repository ARNs
- `ecr_login_command`: AWS CLI command to login to ECR
- `ecr_docker_commands`: Docker commands for each repository

### EKS Outputs
- `eks_cluster_id`: EKS cluster ID
- `eks_cluster_arn`: EKS cluster ARN
- `eks_cluster_name`: EKS cluster name
- `eks_cluster_endpoint`: EKS cluster endpoint
- `eks_cluster_version`: EKS cluster version
- `eks_cluster_security_group_id`: EKS cluster security group ID
- `eks_cluster_certificate_authority_data`: EKS cluster CA certificate
- `eks_cluster_oidc_issuer_url`: EKS OIDC issuer URL
- `eks_cluster_oidc_provider_arn`: EKS OIDC provider ARN
- `eks_node_groups`: EKS node groups
- `eks_node_group_arns`: EKS node group ARNs
- `eks_cluster_iam_role_arn`: EKS cluster IAM role ARN
- `eks_node_group_iam_role_arn`: EKS node group IAM role ARN
- `eks_aws_load_balancer_controller_role_arn`: AWS Load Balancer Controller role ARN
- `eks_alb_arn`: ALB ARN
- `eks_alb_dns_name`: ALB DNS name
- `eks_alb_zone_id`: ALB zone ID
- `eks_alb_hosted_zone_id`: ALB hosted zone ID
- `eks_alb_security_group_id`: ALB security group ID
- `eks_target_groups`: ALB target groups
- `eks_target_group_arns`: ALB target group ARNs
- `eks_listeners`: ALB listeners
- `eks_listener_arns`: ALB listener ARNs
- `eks_addons`: EKS add-ons
- `eks_kubectl_config_command`: kubectl configuration command
- `eks_kubectl_config_file`: kubectl configuration file path
- `eks_cluster_access_commands`: EKS cluster access commands
- `eks_alb_access_info`: ALB access information
- `eks_waf_web_acl_association_id`: WAF Web ACL association ID
- `eks_cloudwatch_log_group_name`: CloudWatch log group name
- `eks_cloudwatch_log_group_arn`: CloudWatch log group ARN

### Karpenter Outputs
- `karpenter_iam_role_arn`: Karpenter IAM role ARN
- `karpenter_instance_profile_name`: Karpenter instance profile name
- `karpenter_sqs_queue_arn`: Karpenter SQS queue ARN
- `karpenter_sqs_queue_url`: Karpenter SQS queue URL
- `karpenter_eventbridge_rule_arn`: Karpenter EventBridge rule ARN
- `karpenter_nodepools`: Karpenter NodePools
- `karpenter_helm_release_name`: Karpenter Helm release name
- `karpenter_helm_release_version`: Karpenter Helm release version
- `karpenter_helm_release_namespace`: Karpenter Helm release namespace
- `karpenter_commands`: Karpenter management commands

### External DNS Outputs
- `external_dns_iam_role_arn`: External DNS IAM role ARN
- `external_dns_helm_release_name`: External DNS Helm release name
- `external_dns_helm_release_version`: External DNS Helm release version
- `external_dns_helm_release_namespace`: External DNS Helm release namespace
- `external_dns_commands`: External DNS management commands

### Route53 Outputs
- `route53_hosted_zone_ids`: Map of hosted zone IDs
- `route53_hosted_zone_names`: Map of hosted zone names
- `route53_hosted_zone_name_servers`: Map of hosted zone name servers
- `route53_hosted_zone_arns`: Map of hosted zone ARNs
- `route53_dns_record_ids`: Map of DNS record IDs
- `route53_health_check_ids`: Map of health check IDs
- `route53_health_check_arns`: Map of health check ARNs
- `route53_name_servers`: Name servers for all hosted zones
- `route53_dns_commands`: DNS management commands

## 🛠️ Module Usage

All modules are reusable and can be called from other configurations:

### EC2 Module
```hcl
module "my_ec2" {
  source = "./modules/ec2"
  
  project_name = "my-project"
  environment  = "prod"
  instance_type = "t3.medium"
  ami_id = "ami-07a3add10195338ad"
  allowed_ssh_cidrs = ["10.0.0.0/8"]
  public_ssh_keys = ["<public_ssh_key>"]
}
```

### S3 Module
```hcl
module "my_s3" {
  source = "./modules/s3"
  
  project_name = "my-project"
  environment  = "prod"
  
  # Simple bucket names
  bucket_names = ["assets", "uploads", "backups"]
  
  # Or environment-specific buckets
  environment_buckets = {
    "prod" = {
      bucket_names = ["static-assets", "uploads"]
      enable_cloudfront = true
      enable_versioning = true
    }
  }
}
```

### Aurora Module
```hcl
module "my_aurora" {
  source = "./modules/aurora"
  
  project_name = "my-project"
  environment  = "prod"
  
  vpc_id = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  ec2_security_group_id = module.ec2.security_group_id
  
  database_name = "myappdb"
  master_username = "admin"
  max_capacity = 16
  min_capacity = 1
}
```

### EKS Module
```hcl
module "my_eks" {
  source = "./modules/eks"
  
  project_name = "my-project"
  environment  = "prod"
  aws_region   = "us-east-1"
  
  # VPC Configuration
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  public_subnet_ids  = module.vpc.public_subnet_ids
  
  # EKS Configuration
  cluster_name                        = "my-cluster"
  cluster_version                     = "1.32"
  cluster_endpoint_private_access     = true
  cluster_endpoint_public_access      = true
  cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
  cluster_enabled_log_types           = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  # Node Group Configuration
  node_groups = {
    general = {
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      disk_size      = 50
      min_size       = 1
      max_size       = 3
      desired_size   = 2
      ami_type       = "AL2_x86_64"
      labels = {
        Environment = "prod"
        NodeType    = "general"
      }
      taints = []
    }
  }
  
  # ALB Configuration
  enable_alb        = true
  alb_name          = "my-alb"
  alb_scheme        = "internet-facing"
  alb_type          = "application"
  
  # Karpenter Configuration
  enable_karpenter     = true
  karpenter_version     = "0.37.0"
  karpenter_nodepools   = {
    default = {
      instance_types = ["t3.medium", "t3.large", "t3.xlarge"]
      capacity_type  = "spot"
      min_capacity   = 0
      max_capacity   = 100
      labels = {
        Environment = "prod"
        NodeType    = "karpenter"
      }
      taints = []
    }
  }
}
```

## 🔧 Security Features

The infrastructure includes comprehensive security features:

### Network Security
- **VPC Isolation**: Custom VPC with public/private subnets
- **Security Groups**: Restrictive inbound rules (HTTP open, SSH restricted)
- **NAT Gateway**: Secure outbound internet access for private subnets
- **Encrypted Transit**: All traffic encrypted in transit

### Instance Security
- **Encrypted Storage**: GP3 encrypted root volume
- **Key-based Authentication**: SSH password authentication disabled
- **Restricted Access**: Root login disabled
- **CloudWatch Monitoring**: Detailed monitoring enabled
- **Elastic IP**: Static IP for consistent access

### Database Security
- **Aurora Encryption**: Database encrypted at rest and in transit
- **Network Isolation**: Database in private subnets only
- **Access Control**: Database accessible only from EC2 instance
- **Secrets Management**: Database credentials stored in AWS Secrets Manager

### Storage Security
- **S3 Encryption**: Buckets encrypted at rest
- **Public Access Blocked**: S3 buckets block public access by default
- **CloudFront Security**: HTTPS-only access with Origin Access Control
- **IAM Roles**: Least privilege access for EC2 instances

### Container Security
- **ECR Encryption**: Container images encrypted at rest
- **Image Scanning**: Vulnerability scanning on push
- **Lifecycle Policies**: Automatic cleanup of old images
- **Access Policies**: Repository-level access control

### Kubernetes Security
- **EKS Encryption**: Control plane and data encryption
- **IAM Integration**: OIDC provider for service accounts
- **Network Policies**: Pod-to-pod communication control
- **RBAC**: Role-based access control
- **Security Groups**: Node-level network security
- **Karpenter Security**: Secure node provisioning with IAM roles
- **External DNS Security**: Secure DNS record management with IAM roles

### DNS Security
- **Route53 Encryption**: DNS queries encrypted in transit
- **Hosted Zone Security**: Private hosted zones for internal services
- **DNS Filtering**: Domain filters for External DNS
- **Health Checks**: Automated DNS health monitoring

## 🧹 Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Note**: The private key will be permanently deleted from Secrets Manager after the 7-day recovery window.

## 🚨 Security Considerations

1. **SSH Access**: Always restrict SSH to specific IP addresses
2. **Key Management**: Store private keys securely and rotate regularly
3. **Database Security**: Use strong passwords and rotate credentials
4. **S3 Buckets**: Review bucket policies and public access settings
5. **ECR Repositories**: Scan images for vulnerabilities regularly
6. **EKS Security**: Enable Pod Security Standards and network policies
7. **Karpenter Security**: Review node provisioning policies and IAM roles
8. **External DNS Security**: Review DNS record management policies and IAM roles
9. **Route53 Security**: Use private hosted zones for internal services
10. **Monitoring**: Enable CloudTrail and CloudWatch for audit logging
11. **Updates**: Regularly update AMIs, Kubernetes versions, and security patches
12. **Backup**: Implement backup strategies for critical data
13. **Network**: Use private subnets for sensitive resources
14. **IAM**: Follow least privilege principle for all IAM roles
15. **Container Security**: Use non-root containers and security contexts
16. **DNS Security**: Monitor DNS queries and implement DNS filtering

## 📝 Troubleshooting

### Common Issues

1. **SSH Connection Refused**: Check security group rules and allowed IPs
2. **Key Pair Errors**: Ensure the key pair exists in the correct region
3. **Secrets Manager Access**: Verify IAM permissions for Secrets Manager
4. **Instance Not Starting**: Check CloudWatch logs for errors
5. **Database Connection Issues**: Verify Aurora security groups and subnet configuration
6. **S3 Access Denied**: Check IAM roles and bucket policies
7. **ECR Push Failures**: Verify ECR login and repository permissions
8. **CloudFront Not Working**: Check Origin Access Control and bucket policies
9. **EKS Cluster Access**: Verify kubectl configuration and IAM permissions
10. **Karpenter Not Scaling**: Check NodePools, IAM roles, and SQS queue configuration
11. **ALB Not Working**: Verify target groups, listeners, and security groups
12. **Pod Scheduling Issues**: Check node capacity, taints, and tolerations
13. **External DNS Not Working**: Check IAM roles, hosted zones, and annotations
14. **DNS Records Not Created**: Verify Route53 permissions and domain configuration
15. **Route53 Access Denied**: Check IAM permissions for Route53 operations

### Getting Help

- Check Terraform logs: `terraform apply -auto-approve 2>&1 | tee terraform.log`
- Review instance logs: `aws logs describe-log-groups --log-group-name-prefix /aws/ec2`
- Verify security group: `aws ec2 describe-security-groups --group-ids <sg-id>`
- Check Aurora status: `aws rds describe-db-clusters --db-cluster-identifier <cluster-id>`
- Verify S3 bucket policies: `aws s3api get-bucket-policy --bucket <bucket-name>`
- Test ECR access: `aws ecr describe-repositories --repository-names <repo-name>`
- Check EKS cluster: `aws eks describe-cluster --name <cluster-name>`
- Verify Karpenter: `kubectl get pods -n karpenter`
- Check NodePools: `kubectl get nodepools`
- Monitor ALB: `aws elbv2 describe-load-balancers --names <alb-name>`
- Check node status: `kubectl get nodes -o wide`
- View Karpenter logs: `kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter`
- Check External DNS: `kubectl get pods -n external-dns`
- View External DNS logs: `kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns`
- Check Route53 zones: `aws route53 list-hosted-zones`
- Verify DNS records: `aws route53 list-resource-record-sets --hosted-zone-id <zone-id>`

## 🌐 External DNS & Route53 Integration

### What is External DNS?

External DNS automatically synchronizes exposed Kubernetes services and Ingresses with DNS providers. It automatically creates, updates, and deletes DNS records based on Kubernetes resources.

### Key Benefits

#### 🔄 Automatic DNS Management
- **Ingress Integration**: Automatically creates DNS records for Ingress resources
- **Service Discovery**: Creates DNS records for LoadBalancer services
- **Subdomain Support**: Automatically manages subdomains within hosted zones
- **Record Cleanup**: Removes DNS records when resources are deleted

#### 🎯 Route53 Integration
- **Hosted Zone Management**: Works with existing Route53 hosted zones
- **Multiple Zones**: Supports multiple hosted zones
- **Health Checks**: Integrates with Route53 health checks
- **Private Zones**: Supports both public and private hosted zones

### External DNS Configuration

The infrastructure includes External DNS configured for:

```hcl
# External DNS Configuration
eks_enable_external_dns = true
eks_external_dns_version = "1.13.1"
eks_external_dns_domain_filters = []  # No domain filtering
eks_external_dns_zone_type = "public"  # Public hosted zones
eks_external_dns_policy = "upsert-only"  # Safe policy
```

### Route53 Hosted Zones

The infrastructure creates Route53 hosted zones for domain management:

```hcl
# Route53 Configuration
route53_enable = true

route53_hosted_zones = {
  "main-domain" = {
    domain_name = "example.com"
    comment     = "Main domain for devops-test pre-prod environment"
  }
}
```

### Security Features

#### 🔒 IAM Integration
- **Least Privilege**: External DNS has minimal required Route53 permissions
- **Service Account**: Uses Kubernetes service account with IAM role
- **OIDC Provider**: Secure authentication via EKS OIDC provider

#### 🛡️ DNS Security
- **Domain Filtering**: Optional domain filters for security
- **Policy Control**: Configurable DNS record management policies
- **Health Checks**: Integration with Route53 health checks
- **Private Zones**: Support for private hosted zones

### Troubleshooting External DNS

#### Common Issues

1. **DNS Records Not Created**
   ```bash
   # Check External DNS logs
   kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns
   
   # Verify IAM permissions
   aws iam get-role-policy --role-name <external-dns-role> --policy-name <policy-name>
   ```

2. **Wrong DNS Records**
   ```bash
   # Check Ingress annotations
   kubectl get ingress <ingress-name> -o yaml
   
   # Verify hosted zone configuration
   aws route53 get-hosted-zone --id <zone-id>
   ```

3. **DNS Resolution Issues**
   ```bash
   # Check nameserver configuration
   dig NS example.com
   
   # Test DNS resolution
   nslookup api.example.com
   ```

## 🚀 Karpenter Auto-Scaling

### What is Karpenter?

Karpenter is AWS's next-generation autoscaler that provides better cost optimization and faster scaling than traditional Cluster Autoscaler. It automatically provisions the right compute resources to handle your pods' requirements.

### Key Benefits

#### 💰 Cost Optimization
- **Spot Instances**: Up to 90% cost savings with spot instances
- **Scale to Zero**: No idle nodes running
- **Right-sizing**: Automatically selects optimal instance types
- **Fast Scaling**: Sub-minute node provisioning

#### ⚡ Performance Features
- **Pod-Driven Scaling**: Automatic node provisioning based on pod requirements
- **Multi-Instance Types**: Flexible instance selection from multiple families
- **Interruption Handling**: Graceful spot instance termination
- **Consolidation**: Automatic node consolidation for efficiency

#### 🔧 Operational Benefits
- **No Manual Scaling**: Fully automated node management
- **Resource Efficiency**: Better resource utilization
- **Fault Tolerance**: Automatic node replacement
- **Cost Visibility**: Detailed cost tracking and optimization

### Karpenter Configuration

The infrastructure includes a default Karpenter NodePool configured for:

```hcl
eks_karpenter_nodepools = {
  default = {
    instance_types = ["t3.medium", "t3.large", "t3.xlarge"]
    capacity_type  = "spot"  # Cost-optimized spot instances
    min_capacity   = 0       # Scale to zero
    max_capacity   = 100     # Scale up to 100 nodes
    ttl_seconds_after_empty = 30      # Remove empty nodes after 30s
    ttl_seconds_until_expired = 2592000  # Expire nodes after 30 days
    labels = {
      Environment = "pre-prod"
      NodeType    = "karpenter"
    }
    taints = []
    requirements = [
      {
        key      = "kubernetes.io/arch"
        operator = "In"
        values   = ["amd64"]
      },
      {
        key      = "karpenter.sh/capacity-type"
        operator = "In"
        values   = ["spot"]
      }
    ]
  }
}
```

### Auto-Scaling Behavior

#### Scale Up Triggers
- Pods can't be scheduled (insufficient resources)
- New workloads requiring specific instance types
- High resource demand

#### Scale Down Triggers
- Nodes underutilized for 30+ seconds
- Empty nodes for 30+ seconds
- Cost optimization opportunities

#### Instance Selection
- **Primary**: t3.medium, t3.large, t3.xlarge
- **Capacity Type**: Spot instances (cost-optimized)
- **Architecture**: AMD64
- **Auto-selection**: Best price/performance ratio

### Karpenter Management Commands

```bash
# Check Karpenter status
kubectl get pods -n karpenter

# Check NodePools
kubectl get nodepools

# Check Karpenter-managed nodes
kubectl get nodes -l karpenter.sh/provisioner-name

# Check Karpenter logs
kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter

# Watch node provisioning
kubectl get nodes -w

# Check node events
kubectl get events --sort-by='.lastTimestamp'

# Scale a deployment to trigger Karpenter
kubectl scale deployment nginx --replicas=10

# Check node utilization
kubectl top nodes
```

## 📄 License

This project is provided as-is for educational and dev use. Please review and customize according to your security requirements.
# terraform-modules
