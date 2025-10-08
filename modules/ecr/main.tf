# Combine both repository configurations
locals {
  # Convert simple repository names to full configuration
  simple_repositories = [
    for name in var.ecr_repository_names : {
      name                 = name
      image_tag_mutability = "MUTABLE"
      scan_on_push         = true
      encryption_type      = "AES256"
      kms_key_id          = null
      lifecycle_policy    = null
      custom_lifecycle_policy = null
    }
  ]
  
  # Merge both repository lists
  all_repositories = concat(var.repositories, local.simple_repositories)
}

# ECR Repositories
resource "aws_ecr_repository" "repositories" {
  for_each = { for repo in local.all_repositories : repo.name => repo }

  name                 = "${var.project_name}-${var.environment}-${each.value.name}"
  image_tag_mutability = each.value.image_tag_mutability

  encryption_configuration {
    encryption_type = each.value.encryption_type
    kms_key        = each.value.kms_key_id
  }

  image_scanning_configuration {
    scan_on_push = each.value.scan_on_push
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-${each.value.name}"
    Environment = var.environment
    Project     = var.project_name
    Repository  = each.value.name
  }
}

# Default Lifecycle Policy for repositories
resource "aws_ecr_lifecycle_policy" "default_policy" {
  for_each = var.enable_lifecycle_policy ? { for repo in local.all_repositories : repo.name => repo if repo.lifecycle_policy == null && repo.custom_lifecycle_policy == null } : {}

  repository = aws_ecr_repository.repositories[each.key].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last ${var.default_lifecycle_policy.max_image_count} images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = var.default_lifecycle_policy.max_image_count
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Delete untagged images older than ${var.default_lifecycle_policy.max_image_age} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.default_lifecycle_policy.max_image_age
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# Custom Lifecycle Policy for repositories with specific policy
resource "aws_ecr_lifecycle_policy" "custom_policy" {
  for_each = { for repo in local.all_repositories : repo.name => repo if repo.custom_lifecycle_policy != null }

  repository = aws_ecr_repository.repositories[each.key].name

  policy = jsonencode({
    rules = each.value.custom_lifecycle_policy.rules
  })
}

# Custom Lifecycle Policy using heredoc syntax
resource "aws_ecr_lifecycle_policy" "heredoc_policy" {
  for_each = { for repo in local.all_repositories : repo.name => repo if repo.lifecycle_policy != null }

  repository = aws_ecr_repository.repositories[each.key].name

  policy = each.value.lifecycle_policy
}

# Repository Policy for cross-account access (optional)
resource "aws_ecr_repository_policy" "repository_policy" {
  for_each = { for repo in local.all_repositories : repo.name => repo }

  repository = aws_ecr_repository.repositories[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPullFromEC2"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }
    ]
  })
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}
