# EKS Module - Main Configuration

# Data sources
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Local values
locals {
  cluster_name = var.cluster_name != "" ? var.cluster_name : "${var.project_name}-${var.environment}-eks"
  alb_name     = var.alb_name != "" ? var.alb_name : "${var.project_name}-${var.environment}-alb"
  
  common_tags = merge(var.tags, {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
  })
}

# KMS Key for EKS logs
resource "aws_kms_key" "eks_logs" {
  description             = "KMS key for EKS CloudWatch logs encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-logs-kms"
  })
}

resource "aws_kms_alias" "eks_logs" {
  name          = "alias/${local.cluster_name}-logs"
  target_key_id = aws_kms_key.eks_logs.key_id
}

# EKS Cluster IAM Role
resource "aws_iam_role" "eks_cluster_role" {
  name = "${local.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# EKS Cluster
resource "aws_eks_cluster" "cluster" {
  name     = local.cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access # tfsec:ignore:aws-eks-no-public-cluster-access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs # tfsec:ignore:aws-eks-no-public-cluster-access-to-cidr
  }

  enabled_cluster_log_types = var.cluster_enabled_log_types

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_cloudwatch_log_group.cluster_logs
  ]

  tags = local.common_tags
}

# CloudWatch Log Group for EKS Cluster
resource "aws_cloudwatch_log_group" "cluster_logs" {
  name              = "/aws/eks/${local.cluster_name}/cluster"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.eks_logs.arn

  tags = local.common_tags
}

# EKS Node Group IAM Role
resource "aws_iam_role" "eks_node_group_role" {
  name = "${local.cluster_name}-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group_role.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group_role.name
}

# Security Group for EKS Nodes
resource "aws_security_group" "eks_nodes" {
  name_prefix = "${local.cluster_name}-nodes-"
  description = "Security group for EKS nodes"
  vpc_id      = var.vpc_id

  # Allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-egress-sgr
  }

  # Allow inbound traffic from EKS cluster
  ingress {
    description = "HTTPS from EKS cluster"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Allow inbound traffic from ALB
  ingress {
    description = "HTTP from ALB"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Allow inbound traffic from ALB
  ingress {
    description = "HTTPS from ALB"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Allow node-to-node communication
  ingress {
    description = "Node-to-node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-nodes-sg"
  })
}

# Launch Template for EKS Node Groups with gp3 storage
resource "aws_launch_template" "node_group" {
  for_each = var.node_groups

  name_prefix   = "${local.cluster_name}-${each.key}-"
  image_id      = data.aws_ami.eks_optimized.id
  instance_type = each.value.instance_types[0]

  vpc_security_group_ids = [aws_security_group.eks_nodes.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = each.value.disk_size
      encrypted             = true
      kms_key_id           = aws_kms_key.eks_secrets.arn
      iops                 = 3000
      throughput           = 125
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 2
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    cluster_name = local.cluster_name
    cluster_endpoint = aws_eks_cluster.cluster.endpoint
    cluster_ca = aws_eks_cluster.cluster.certificate_authority[0].data
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.cluster_name}-${each.key}-node"
      NodeGroup = each.key
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Data source for EKS optimized AMI
data "aws_ami" "eks_optimized" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.cluster_version}-v*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# EKS Managed Node Groups
resource "aws_eks_node_group" "node_groups" {
  for_each = var.node_groups

  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.eks_node_group_role.arn
  subnet_ids      = var.private_subnet_ids

  instance_types = each.value.instance_types
  capacity_type  = each.value.capacity_type
  disk_size      = each.value.disk_size
  ami_type       = each.value.ami_type

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  labels = each.value.labels

  # Update configuration for rolling updates
  update_config {
    max_unavailable_percentage = 25
  }

  # Launch template for advanced storage configuration
  launch_template {
    id      = aws_launch_template.node_group[each.key].id
    version = aws_launch_template.node_group[each.key].latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry_policy
  ]

  tags = merge(local.common_tags, {
    NodeGroup = each.key
  })
}

# EKS Add-ons
resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "vpc-cni"
  
  # Use the latest compatible version for Kubernetes 1.32
  addon_version = "v1.18.1-eksbuild.1"
  
  tags = local.common_tags
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "coredns"
  
  # Use the latest compatible version for Kubernetes 1.32
  addon_version = "v1.11.1-eksbuild.4"
  
  depends_on = [aws_eks_node_group.node_groups]
  
  tags = local.common_tags
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "kube-proxy"
  
  # Use the latest compatible version for Kubernetes 1.32
  addon_version = "v1.32.1-eksbuild.1"
  
  tags = local.common_tags
}

resource "aws_eks_addon" "ebs_csi_driver" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "aws-ebs-csi-driver"
  
  # Use the latest compatible version for Kubernetes 1.32
  addon_version = "v1.25.0-eksbuild.1"
  
  tags = local.common_tags
}

# Application Load Balancer (ALB)
resource "aws_lb" "alb" {
  count = var.enable_alb ? 1 : 0

  name               = local.alb_name
  internal           = var.alb_scheme == "internal" # tfsec:ignore:aws-elb-alb-not-public
  load_balancer_type = var.alb_type
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = false
  drop_invalid_header_fields = true

  tags = merge(local.common_tags, {
    Name = local.alb_name
  })
}

# ALB Security Group
resource "aws_security_group" "alb" {
  count = var.enable_alb ? 1 : 0

  name_prefix = "${local.alb_name}-"
  description = "Security group for EKS Application Load Balancer"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs # tfsec:ignore:aws-ec2-no-public-ingress-sgr
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs # tfsec:ignore:aws-ec2-no-public-ingress-sgr
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-egress-sgr
  }

  tags = merge(local.common_tags, {
    Name = "${local.alb_name}-sg"
  })
}

# ALB Target Groups
resource "aws_lb_target_group" "target_groups" {
  for_each = var.enable_alb ? var.alb_target_groups : {}

  name     = "${local.alb_name}-${each.key}"
  port     = each.value.port
  protocol = each.value.protocol
  vpc_id   = var.vpc_id

  target_type = each.value.target_type

  health_check {
    enabled             = true
    healthy_threshold   = each.value.healthy_threshold
    unhealthy_threshold = each.value.unhealthy_threshold
    timeout             = each.value.health_check_timeout
    interval            = each.value.health_check_interval
    path                = each.value.health_check_path
    port                = each.value.health_check_port
    protocol            = each.value.health_check_protocol
    matcher             = each.value.health_check_matcher
  }

  dynamic "stickiness" {
    for_each = each.value.stickiness != null ? [each.value.stickiness] : []
    content {
      enabled         = stickiness.value.enabled
      type            = stickiness.value.type
      cookie_duration = 86400
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.alb_name}-${each.key}-tg"
  })
}

# ALB Listeners
resource "aws_lb_listener" "listeners" {
  for_each = var.enable_alb ? var.alb_listeners : {}

  load_balancer_arn = aws_lb.alb[0].arn
  port              = each.value.port
  protocol          = each.value.protocol

  ssl_policy      = each.value.ssl_policy
  certificate_arn = each.value.certificate_arn != null ? each.value.certificate_arn : var.ssl_certificate_arn

  default_action {
    type = each.value.default_action.type

    dynamic "forward" {
      for_each = each.value.default_action.type == "forward" ? [1] : []
      content {
        target_group {
          arn = aws_lb_target_group.target_groups[each.value.default_action.target_group_key].arn
        }
      }
    }

    dynamic "redirect" {
      for_each = each.value.default_action.type == "redirect" ? [each.value.default_action.redirect] : []
      content {
        port        = redirect.value.port
        protocol    = redirect.value.protocol
        status_code = redirect.value.status_code
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.alb_name}-${each.key}-listener"
  })
}

# AWS Load Balancer Controller IAM Role
resource "aws_iam_role" "aws_load_balancer_controller" {
  count = var.enable_alb ? 1 : 0

  name = "${local.cluster_name}-aws-load-balancer-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks[0].arn
        }
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller"
            "${replace(aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:aud": "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# AWS Load Balancer Controller IAM Policy
resource "aws_iam_policy" "aws_load_balancer_controller" {
  count = var.enable_alb ? 1 : 0

  name        = "${local.cluster_name}-aws-load-balancer-controller"
  description = "IAM policy for AWS Load Balancer Controller"

  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:DescribeProtection",
          "shield:GetSubscriptionState",
          "shield:DescribeSubscription",
          "shield:CreateProtection",
          "shield:DeleteProtection"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          StringEquals = {
            "ec2:CreateAction": "CreateSecurityGroup"
          }
          Null = {
            "aws:RequestedRegion": "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestedRegion": "false"
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:DeleteRule"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ]
        Resource = [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
        ]
        Condition = {
          Null = {
            "aws:RequestedRegion": "false"
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestedRegion": "false"
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets"
        ]
        Resource = "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:ModifyRule"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "aws_load_balancer_controller" {
  count = var.enable_alb ? 1 : 0

  policy_arn = aws_iam_policy.aws_load_balancer_controller[0].arn
  role       = aws_iam_role.aws_load_balancer_controller[0].name
}

# OIDC Identity Provider for EKS
resource "aws_iam_openid_connect_provider" "eks" {
  count = var.enable_alb ? 1 : 0

  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks[0].certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.cluster.identity[0].oidc[0].issuer

  tags = local.common_tags
}

# TLS Certificate for OIDC
data "tls_certificate" "eks" {
  count = var.enable_alb ? 1 : 0

  url = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

# Associate WAF Web ACL with ALB (if enabled)
resource "aws_wafv2_web_acl_association" "alb" {
  count = var.enable_alb && var.enable_waf ? 1 : 0

  resource_arn = aws_lb.alb[0].arn
  web_acl_arn  = var.waf_web_acl_arn
}


# External DNS IAM Role
resource "aws_iam_role" "external_dns" {
  count = var.enable_external_dns ? 1 : 0

  name = "${local.cluster_name}-external-dns"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks[0].arn
        }
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:sub": "system:serviceaccount:external-dns:external-dns"
            "${replace(aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:aud": "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# External DNS IAM Policy
resource "aws_iam_policy" "external_dns" {
  count = var.enable_external_dns ? 1 : 0

  name        = "${local.cluster_name}-external-dns"
  description = "IAM policy for External DNS"

  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets"
        ]
        Resource = [
          "arn:aws:route53:::hostedzone/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "route53:ListHostedZones",
          "route53:ListResourceRecordSets",
          "route53:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "external_dns" {
  count = var.enable_external_dns ? 1 : 0

  policy_arn = aws_iam_policy.external_dns[0].arn
  role       = aws_iam_role.external_dns[0].name
}

# Random password for Grafana admin
resource "random_password" "grafana_admin_password" {
  count = var.enable_prometheus_stack ? 1 : 0
  
  length  = 32
  special = true
  upper   = true
  lower   = true
  numeric = true
}

# Store Grafana admin password in Secrets Manager
resource "aws_secretsmanager_secret" "grafana_admin_password" {
  count = var.enable_prometheus_stack ? 1 : 0
  
  name                    = "${local.cluster_name}-grafana-admin-password"
  description             = "Grafana admin password for ${local.cluster_name}"
  recovery_window_in_days  = 7
  kms_key_id              = aws_kms_key.eks_secrets.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-grafana-admin-password"
  })
}

resource "aws_secretsmanager_secret_version" "grafana_admin_password" {
  count = var.enable_prometheus_stack ? 1 : 0
  
  secret_id     = aws_secretsmanager_secret.grafana_admin_password[0].id
  secret_string = random_password.grafana_admin_password[0].result
}

# StorageClass for gp3 with encryption
resource "kubernetes_storage_class" "gp3_encrypted" {
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }
  
  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy        = "Delete"
  volume_binding_mode   = "WaitForFirstConsumer"
  allow_volume_expansion = true
  
  parameters = {
    type       = "gp3"
    encrypted  = "true"
    kmsKeyId   = aws_kms_key.eks_secrets.arn
    fsType     = "ext4"
    iops       = "3000"
    throughput = "125"
  }
}

# Prometheus Stack Helm Release
resource "helm_release" "prometheus_stack" {
  count = var.enable_prometheus_stack ? 1 : 0

  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = var.prometheus_stack_version
  namespace  = "monitoring"

  create_namespace = true

  values = [
    yamlencode({
      # Prometheus Configuration
      prometheus = {
        prometheusSpec = {
          retention = "30d"
          resources = {
            requests = {
              cpu    = "500m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "1000m"
              memory = "2Gi"
            }
          }
          storageSpec = {
            volumeClaimTemplate = {
              spec = {
                storageClassName = "gp3"
                accessModes      = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "50Gi"
                  }
                }
              }
            }
          }
          nodeSelector = {
            "kubernetes.io/os" = "linux"
          }
          tolerations = []
        }
      }

      # Grafana Configuration
      grafana = {
        enabled = true
        adminPassword = random_password.grafana_admin_password[0].result
        resources = {
          requests = {
            cpu    = "200m"
            memory = "256Mi"
          }
          limits = {
            cpu    = "500m"
            memory = "512Mi"
          }
        }
        persistence = {
          enabled = true
          size    = "10Gi"
          storageClassName = "gp3"
        }
        service = {
          type = "LoadBalancer"
          annotations = {
            "service.beta.kubernetes.io/aws-load-balancer-type" = "nlb"
            "service.beta.kubernetes.io/aws-load-balancer-scheme" = "internal"
          }
        }
        nodeSelector = {
          "kubernetes.io/os" = "linux"
        }
        tolerations = []
      }

      # AlertManager Configuration
      alertmanager = {
        enabled = true
        alertmanagerSpec = {
          resources = {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "256Mi"
            }
          }
          storage = {
            volumeClaimTemplate = {
              spec = {
                storageClassName = "gp3"
                accessModes      = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "10Gi"
                  }
                }
              }
            }
          }
          nodeSelector = {
            "kubernetes.io/os" = "linux"
          }
          tolerations = []
        }
      }

      # Node Exporter Configuration
      nodeExporter = {
        enabled = true
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "200m"
            memory = "256Mi"
          }
        }
        nodeSelector = {
          "kubernetes.io/os" = "linux"
        }
        tolerations = []
      }

      # Kube State Metrics Configuration
      kubeStateMetrics = {
        enabled = true
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "200m"
            memory = "256Mi"
          }
        }
        nodeSelector = {
          "kubernetes.io/os" = "linux"
        }
        tolerations = []
      }

      # Default dashboards and rules
      defaultRules = {
        create = true
      }

      # Service monitors
      prometheusOperator = {
        enabled = true
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "200m"
            memory = "256Mi"
          }
        }
        nodeSelector = {
          "kubernetes.io/os" = "linux"
        }
        tolerations = []
      }
    })
  ]

  depends_on = [
    aws_eks_node_group.node_groups
  ]
}

# Metrics Server Helm Release
resource "helm_release" "metrics_server" {
  count = var.enable_metrics_server ? 1 : 0

  name       = "metrics-server"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = var.metrics_server_version
  namespace  = "kube-system"

  values = [
    yamlencode({
      args = [
        "--cert-dir=/tmp",
        "--secure-port=4443",
        "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
        "--kubelet-use-node-status-port",
        "--metric-resolution=15s"
      ]
      resources = {
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
        limits = {
          cpu    = "200m"
          memory = "256Mi"
        }
      }
      nodeSelector = {
        "kubernetes.io/os" = "linux"
      }
      tolerations = []
      affinity = {
        nodeAffinity = {
          requiredDuringSchedulingIgnoredDuringExecution = {
            nodeSelectorTerms = [
              {
                matchExpressions = [
                  {
                    key      = "kubernetes.io/os"
                    operator = "In"
                    values   = ["linux"]
                  }
                ]
              }
            ]
          }
        }
      }
    })
  ]
}

# AWS Load Balancer Controller Helm Release
resource "helm_release" "aws_load_balancer_controller" {
  count = var.enable_alb ? 1 : 0

  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = var.alb_controller_version
  namespace  = "kube-system"

  values = [
    yamlencode({
      clusterName = local.cluster_name
      serviceAccount = {
        create = false
        name   = "aws-load-balancer-controller"
        annotations = {
          "eks.amazonaws.com/role-arn" = aws_iam_role.aws_load_balancer_controller[0].arn
        }
      }
      region = var.aws_region
      vpcId = var.vpc_id
      resources = {
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
        limits = {
          cpu    = "200m"
          memory = "256Mi"
        }
      }
      nodeSelector = {
        "kubernetes.io/os" = "linux"
      }
      tolerations = []
      affinity = {
        nodeAffinity = {
          requiredDuringSchedulingIgnoredDuringExecution = {
            nodeSelectorTerms = [
              {
                matchExpressions = [
                  {
                    key      = "kubernetes.io/os"
                    operator = "In"
                    values   = ["linux"]
                  }
                ]
              }
            ]
          }
        }
      }
      logLevel = "info"
      enableServiceMutatorWebhook = false
    })
  ]

  depends_on = [
    aws_iam_role_policy_attachment.aws_load_balancer_controller
  ]
}

# External DNS Helm Release
resource "helm_release" "external_dns" {
  count = var.enable_external_dns ? 1 : 0

  name       = "external-dns"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = var.external_dns_version
  namespace  = "external-dns"

  create_namespace = true

  values = [
    yamlencode({
      serviceAccount = {
        create = true
        name   = "external-dns"
        annotations = {
          "eks.amazonaws.com/role-arn" = aws_iam_role.external_dns[0].arn
        }
      }
      provider = "aws"
      aws = {
        region = var.aws_region
      }
      domainFilters = var.external_dns_domain_filters
      zoneType = var.external_dns_zone_type
      policy = var.external_dns_policy
      txtOwnerId = var.external_dns_txt_owner_id != "" ? var.external_dns_txt_owner_id : local.cluster_name
      txtPrefix = var.external_dns_txt_prefix
      annotationFilter = var.external_dns_annotation_filter
      labelFilter = var.external_dns_label_filter
      logLevel = "info"
      logFormat = "json"
      resources = {
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
        limits = {
          cpu    = "200m"
          memory = "256Mi"
        }
      }
      nodeSelector = {
        "kubernetes.io/os" = "linux"
      }
      tolerations = []
      affinity = {}
    })
  ]

  depends_on = [
    aws_eks_node_group.node_groups,
    aws_iam_role_policy_attachment.external_dns
  ]
}

# KMS Key for EKS Secrets Encryption
resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-secrets-kms"
  })
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/${local.cluster_name}-secrets"
  target_key_id = aws_kms_key.eks_secrets.key_id
}
