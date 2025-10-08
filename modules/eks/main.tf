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
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
  }

  enabled_cluster_log_types = var.cluster_enabled_log_types

  dynamic "encryption_config" {
    for_each = var.cluster_encryption_config.provider_key_arn != null ? [1] : []
    content {
      provider {
        key_arn = var.cluster_encryption_config.provider_key_arn
      }
      resources = var.cluster_encryption_config.resources
    }
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
  internal           = var.alb_scheme == "internal"
  load_balancer_type = var.alb_type
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = false

  tags = merge(local.common_tags, {
    Name = local.alb_name
  })
}

# ALB Security Group
resource "aws_security_group" "alb" {
  count = var.enable_alb ? 1 : 0

  name_prefix = "${local.alb_name}-"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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

  policy = jsonencode({
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
  count = var.enable_alb && var.enable_waf && var.waf_web_acl_arn != null ? 1 : 0

  resource_arn = aws_lb.alb[0].arn
  web_acl_arn  = var.waf_web_acl_arn
}

# Karpenter IAM Role
resource "aws_iam_role" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name = "${local.cluster_name}-karpenter"

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
            "${replace(aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:sub": "system:serviceaccount:karpenter:karpenter"
            "${replace(aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:aud": "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# Karpenter IAM Policy
resource "aws_iam_policy" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name        = "${local.cluster_name}-karpenter"
  description = "IAM policy for Karpenter"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "iam:PassRole",
          "ec2:DescribeImages",
          "ec2:RunInstances",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeInstanceTypeOfferings",
          "ec2:DescribeAvailabilityZones",
          "ec2:DeleteLaunchTemplate",
          "ec2:CreateTags",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateFleet",
          "ec2:DescribeSpotPriceHistory",
          "pricing:GetProducts"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",
          "ec2:DeleteLaunchTemplate"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "ec2:ResourceTag/karpenter.sh/cluster": local.cluster_name
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  policy_arn = aws_iam_policy.karpenter[0].arn
  role       = aws_iam_role.karpenter[0].name
}

# Karpenter Instance Profile
resource "aws_iam_instance_profile" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name = "${local.cluster_name}-karpenter"
  role = aws_iam_role.karpenter[0].name

  tags = local.common_tags
}

# Karpenter Helm Release
resource "helm_release" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name       = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  version    = var.karpenter_version
  namespace  = "karpenter"

  create_namespace = true

  values = [
    yamlencode({
      settings = {
        aws = {
          clusterName = aws_eks_cluster.cluster.name
          defaultInstanceProfile = aws_iam_instance_profile.karpenter[0].name
          interruptionQueue = aws_sqs_queue.karpenter[0].name
        }
      }
      controller = {
        resources = {
          requests = {
            cpu = "1"
            memory = "1Gi"
          }
          limits = {
            cpu = "1"
            memory = "1Gi"
          }
        }
      }
    })
  ]

  depends_on = [
    aws_eks_node_group.node_groups,
    aws_sqs_queue.karpenter,
    aws_sqs_queue_policy.karpenter
  ]
}

# SQS Queue for Karpenter Interruption Handling
resource "aws_sqs_queue" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name = "${local.cluster_name}-karpenter-interruption"

  message_retention_seconds = 300
  visibility_timeout_seconds = 30

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-karpenter-interruption"
  })
}

# SQS Queue Policy for Karpenter
resource "aws_sqs_queue_policy" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  queue_url = aws_sqs_queue.karpenter[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sqs:SendMessage"
        Resource = aws_sqs_queue.karpenter[0].arn
      }
    ]
  })
}

# EventBridge Rule for Spot Interruption
resource "aws_cloudwatch_event_rule" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name        = "${local.cluster_name}-karpenter-interruption"
  description = "Karpenter Spot Instance Interruption"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Spot Instance Interruption Warning"]
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  rule      = aws_cloudwatch_event_rule.karpenter[0].name
  target_id = "KarpenterInterruptionQueueTarget"
  arn       = aws_sqs_queue.karpenter[0].arn
}

# Karpenter NodePools
resource "kubectl_manifest" "karpenter_nodepools" {
  for_each = var.enable_karpenter ? var.karpenter_nodepools : {}

  yaml_body = yamlencode({
    apiVersion = "karpenter.sh/v1beta1"
    kind       = "NodePool"
    metadata = {
      name = each.key
    }
    spec = {
      template = {
        metadata = {
          labels = merge(each.value.labels, {
            "karpenter.sh/nodepool" = each.key
          })
        }
        spec = {
          nodeClassRef = {
            apiVersion = "karpenter.k8s.aws/v1beta1"
            kind       = "EC2NodeClass"
            name       = "default"
          }
          requirements = concat([
            {
              key      = "kubernetes.io/arch"
              operator = "In"
              values   = ["amd64"]
            },
            {
              key      = "karpenter.sh/capacity-type"
              operator = "In"
              values   = [each.value.capacity_type]
            }
          ], each.value.requirements)
          taints = each.value.taints
        }
      }
      limits = {
        cpu    = each.value.max_capacity
        memory = "1000Gi"
      }
      disruption = {
        consolidateAfter = "30s"
        consolidateWhen  = "Underutilized"
        expireAfter      = "${each.value.ttl_seconds_until_expired}s"
      }
    }
  })

  depends_on = [helm_release.karpenter]
}

# Karpenter EC2NodeClass
resource "kubectl_manifest" "karpenter_nodeclass" {
  count = var.enable_karpenter ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "karpenter.k8s.aws/v1beta1"
    kind       = "EC2NodeClass"
    metadata = {
      name = "default"
    }
    spec = {
      amiFamily = "AL2"
      instanceStorePolicy = "RAID0"
      userData = base64encode(templatefile("${path.module}/karpenter-userdata.sh", {
        cluster_name = aws_eks_cluster.cluster.name
        cluster_endpoint = aws_eks_cluster.cluster.endpoint
        cluster_ca = aws_eks_cluster.cluster.certificate_authority[0].data
      }))
      role = aws_iam_role.karpenter[0].name
      subnetSelectorTerms = [
        {
          tags = {
            "karpenter.sh/discovery" = local.cluster_name
          }
        }
      ]
      securityGroupSelectorTerms = [
        {
          tags = {
            "karpenter.sh/discovery" = local.cluster_name
          }
        }
      ]
      tags = merge(local.common_tags, {
        "karpenter.sh/discovery" = local.cluster_name
      })
    }
  })

  depends_on = [helm_release.karpenter]
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

  policy = jsonencode({
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
