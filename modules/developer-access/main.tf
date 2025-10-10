# Developer Readonly Access Module
# This module provides secure readonly access for developer teams

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}


# Local values
locals {
  common_tags = merge(var.tags, {
    Environment = var.environment
    Project     = var.project_name
    Module      = "developer-access"
    Purpose     = "readonly-access"
  })
}

# IAM Group for Developers
resource "aws_iam_group" "developers" { # tfsec:ignore:aws-iam-enforce-group-mfa
  for_each = toset(var.developer_groups)
  
  name = "${var.project_name}-${var.environment}-${each.key}"
}

# IAM Users for Developers
resource "aws_iam_user" "developers" {
  for_each = toset(var.developer_users)
  
  name = "${var.project_name}-${var.environment}-${each.key}"
  path = "/developers/"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-${each.key}-user"
    Role = "developer"
  })
}

# Add users to developer groups
resource "aws_iam_group_membership" "developers" {
  for_each = toset(var.developer_groups)
  
  name  = "${var.project_name}-${var.environment}-${each.key}-membership"
  users = var.developer_users
  group = aws_iam_group.developers[each.key].name
}

# EKS Readonly Policy
resource "aws_iam_policy" "eks_readonly" {
  name        = "${var.project_name}-${var.environment}-eks-readonly"
  description = "Readonly access to EKS cluster and related resources"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:DescribeNodegroup",
          "eks:ListNodegroups",
          "eks:DescribeAddon",
          "eks:ListAddons",
          "eks:DescribeUpdate",
          "eks:ListUpdates",
          "eks:AccessKubernetesApi"
        ]
        Resource = [
          "arn:aws:eks:*:*:cluster/${var.eks_cluster_name}",
          "arn:aws:eks:*:*:nodegroup/${var.eks_cluster_name}/*",
          "arn:aws:eks:*:*:addon/${var.eks_cluster_name}/*"
        ]
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "eks:ListClusters"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Aurora Readonly Policy
resource "aws_iam_policy" "aurora_readonly" {
  name        = "${var.project_name}-${var.environment}-aurora-readonly"
  description = "Readonly access to Aurora database"
  
  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBClusters",
          "rds:DescribeDBClusterEndpoints",
          "rds:DescribeDBClusterParameterGroups",
          "rds:DescribeDBClusterParameters",
          "rds:DescribeDBClusterSnapshots",
          "rds:DescribeDBInstances",
          "rds:DescribeDBSubnetGroups",
          "rds:DescribeDBClusterMembers",
          "rds:DescribeDBClusterBacktracks",
          "rds:DescribeDBClusterAutomatedBackups",
          "rds:DescribeDBClusterSnapshotAttributes",
          "rds:DescribeDBClusterEndpoints",
          "rds:DescribeDBClusterParameterGroups",
          "rds:DescribeDBClusterParameters",
          "rds:DescribeDBClusterSnapshots",
          "rds:DescribeDBInstances",
          "rds:DescribeDBSubnetGroups",
          "rds:DescribeDBClusterMembers",
          "rds:DescribeDBClusterBacktracks",
          "rds:DescribeDBClusterAutomatedBackups",
          "rds:DescribeDBClusterSnapshotAttributes"
        ]
        Resource = [
          "arn:aws:rds:*:*:cluster:${var.aurora_cluster_identifier}",
          "arn:aws:rds:*:*:db:${var.aurora_cluster_identifier}-*"
        ]
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBClusters",
          "rds:DescribeDBInstances"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# S3 Readonly Policy
resource "aws_iam_policy" "s3_readonly" {
  name        = "${var.project_name}-${var.environment}-s3-readonly"
  description = "Readonly access to S3 buckets"
  
  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketAcl",
          "s3:GetBucketCORS",
          "s3:GetBucketLifecycleConfiguration",
          "s3:GetBucketLogging",
          "s3:GetBucketNotification",
          "s3:GetBucketRequestPayment",
          "s3:GetBucketTagging",
          "s3:GetBucketWebsite",
          "s3:GetEncryptionConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetReplicationConfiguration"
        ]
        Resource = concat(
          var.s3_bucket_arns,
          [for arn in var.s3_bucket_arns : "${arn}/*"]
        )
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# ECR Readonly Policy
resource "aws_iam_policy" "ecr_readonly" {
  name        = "${var.project_name}-${var.environment}-ecr-readonly"
  description = "Readonly access to ECR repositories"
  
  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages",
          "ecr:BatchGetRepositoryScanningConfiguration",
          "ecr:GetRepositoryScanningConfiguration",
          "ecr:ListTagsForResource",
          "ecr:GetLifecyclePolicy",
          "ecr:GetRepositoryPolicy"
        ]
        Resource = var.ecr_repository_arns
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# CloudWatch Readonly Policy
resource "aws_iam_policy" "cloudwatch_readonly" {
  name        = "${var.project_name}-${var.environment}-cloudwatch-readonly"
  description = "Readonly access to CloudWatch logs and metrics"
  
  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "logs:GetLogGroupFields",
          "logs:GetQueryResults",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:TestMetricFilter",
          "logs:DescribeMetricFilters",
          "logs:DescribeResourcePolicies",
          "logs:DescribeSubscriptionFilters",
          "logs:ListTagsLogGroup",
          "logs:ListTagsLogStream",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DescribeAlarmHistory",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# EC2 Readonly Policy
resource "aws_iam_policy" "ec2_readonly" {
  name        = "${var.project_name}-${var.environment}-ec2-readonly"
  description = "Readonly access to EC2 instances and related resources"
  
  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstanceAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumeStatus",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeTags",
          "ec2:DescribeRegions",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeElasticGpus",
          "ec2:DescribeFpgaImages",
          "ec2:DescribeHosts",
          "ec2:DescribeIdFormat",
          "ec2:DescribeIdentityIdFormat",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeInstanceCreditSpecifications",
          "ec2:DescribeInstanceEventNotificationAttributes",
          "ec2:DescribeInstanceEventWindows",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeInstanceTypeOfferings",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:DescribePlacementGroups",
          "ec2:DescribeReservedInstances",
          "ec2:DescribeReservedInstancesModifications",
          "ec2:DescribeReservedInstancesOfferings",
          "ec2:DescribeSpotFleetInstances",
          "ec2:DescribeSpotFleetRequestHistory",
          "ec2:DescribeSpotFleetRequests",
          "ec2:DescribeSpotInstanceRequests",
          "ec2:DescribeSpotPriceHistory",
          "ec2:DescribeStaleSecurityGroups",
          "ec2:DescribeTransitGateways",
          "ec2:DescribeTransitGatewayAttachments",
          "ec2:DescribeTransitGatewayRouteTables",
          "ec2:DescribeTransitGatewayVpcAttachments",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeVpcClassicLink",
          "ec2:DescribeVpcClassicLinkDnsSupport",
          "ec2:DescribeVpcEndpointConnections",
          "ec2:DescribeVpcEndpointServiceConfigurations",
          "ec2:DescribeVpcEndpointServices",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeVpnConnections",
          "ec2:DescribeVpnGateways"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Route53 Readonly Policy
resource "aws_iam_policy" "route53_readonly" {
  name        = "${var.project_name}-${var.environment}-route53-readonly"
  description = "Readonly access to Route53 DNS records"
  
  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "route53:GetHostedZone",
          "route53:ListHostedZones",
          "route53:ListHostedZonesByName",
          "route53:GetHostedZoneCount",
          "route53:ListResourceRecordSets",
          "route53:GetChange",
          "route53:ListTagsForResource",
          "route53:ListTagsForResources",
          "route53:GetHealthCheck",
          "route53:ListHealthChecks",
          "route53:GetHealthCheckStatus",
          "route53:GetHealthCheckLastFailureReason",
          "route53:GetHealthCheckCount",
          "route53:GetReusableDelegationSet",
          "route53:ListReusableDelegationSets",
          "route53:GetTrafficPolicy",
          "route53:ListTrafficPolicies",
          "route53:GetTrafficPolicyInstance",
          "route53:ListTrafficPolicyInstances",
          "route53:GetTrafficPolicyInstanceCount",
          "route53:GetAccountLimit",
          "route53:GetHostedZoneLimit",
          "route53:GetReusableDelegationSetLimit"
        ]
        Resource = "*" # tfsec:ignore:aws-iam-no-policy-wildcards
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# Attach policies to developer groups
resource "aws_iam_group_policy_attachment" "eks_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.eks_readonly.arn
}

resource "aws_iam_group_policy_attachment" "aurora_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.aurora_readonly.arn
}

resource "aws_iam_group_policy_attachment" "s3_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.s3_readonly.arn
}

resource "aws_iam_group_policy_attachment" "ecr_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.ecr_readonly.arn
}

resource "aws_iam_group_policy_attachment" "cloudwatch_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.cloudwatch_readonly.arn
}

resource "aws_iam_group_policy_attachment" "ec2_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.ec2_readonly.arn
}

resource "aws_iam_group_policy_attachment" "route53_readonly" {
  for_each = toset(var.developer_groups)
  
  group      = aws_iam_group.developers[each.key].name
  policy_arn = aws_iam_policy.route53_readonly.arn
}

