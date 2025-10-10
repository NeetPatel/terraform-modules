# Combine all bucket configurations
locals {
  # Convert simple bucket names to full configuration
  simple_buckets = [
    for name in var.bucket_names : {
      name                 = name
      enable_versioning    = true
      block_public_access  = true
      enable_cloudfront    = true
      default_root_object  = "index.html"
      price_class         = "PriceClass_100"
    }
  ]
  
  # Convert single bucket to configuration
  single_bucket = var.bucket_name != "" ? [{
    name                 = var.bucket_name
    enable_versioning    = var.enable_versioning
    block_public_access  = var.block_public_access
    enable_cloudfront    = true
    default_root_object  = var.default_root_object
    price_class         = var.price_class
  }] : []
  
  # Convert environment-specific buckets to configuration
  env_buckets = flatten([
    for env_name, env_config in var.environment_buckets : [
      for bucket_name in env_config.bucket_names : {
        name                 = "${env_name}-${bucket_name}"
        enable_versioning    = env_config.enable_versioning
        block_public_access  = env_config.block_public_access
        enable_cloudfront    = env_config.enable_cloudfront
        default_root_object  = "index.html"
        price_class         = "PriceClass_100"
        environment         = env_name
      }
    ]
  ])
  
  # Merge all bucket lists
  all_buckets = concat(var.buckets, local.simple_buckets, local.single_bucket, local.env_buckets)
}

# S3 Buckets
resource "aws_s3_bucket" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket }

  bucket = "${var.project_name}-${var.environment}-${each.value.name}"

  tags = {
    Name        = "${var.project_name}-${var.environment}-${each.value.name}"
    Environment = var.environment
    Project     = var.project_name
    Bucket      = each.value.name
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket }

  bucket = aws_s3_bucket.buckets[each.key].id
  versioning_configuration {
    status = each.value.enable_versioning ? "Enabled" : "Suspended"
  }
}

# S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket }

  bucket = aws_s3_bucket.buckets[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket }

  bucket = aws_s3_bucket.buckets[each.key].id

  block_public_acls       = each.value.block_public_access
  block_public_policy     = each.value.block_public_access
  ignore_public_acls      = each.value.block_public_access
  restrict_public_buckets = each.value.block_public_access
}

# CloudFront Origin Access Control (one per bucket that needs CloudFront)
resource "aws_cloudfront_origin_access_control" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket if bucket.enable_cloudfront }

  name                              = "${var.project_name}-${var.environment}-${each.value.name}-oac"
  description                       = "OAC for ${var.project_name} ${each.value.name} bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront Distributions (one per bucket that needs CloudFront)
resource "aws_cloudfront_distribution" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket if bucket.enable_cloudfront }

  origin {
    domain_name              = aws_s3_bucket.buckets[each.key].bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.buckets[each.key].id
    origin_id                = "S3-${aws_s3_bucket.buckets[each.key].bucket}"
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CloudFront distribution for ${var.project_name} ${var.environment} ${each.value.name}"
  default_root_object = each.value.default_root_object
  web_acl_id         = aws_wafv2_web_acl.cloudfront.arn

  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods        = ["GET", "HEAD"]
    target_origin_id      = "S3-${aws_s3_bucket.buckets[each.key].bucket}"
    compress              = true
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  # Cache behavior for static assets
  ordered_cache_behavior {
    path_pattern     = "/static/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.buckets[each.key].bucket}"
    compress         = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 86400
    max_ttl     = 31536000
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = each.value.price_class

  logging_config {
    bucket          = aws_s3_bucket.cloudfront_logs.bucket_domain_name
    include_cookies = false
    prefix         = "cloudfront-logs/"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-${each.value.name}-cloudfront"
    Environment = var.environment
    Project     = var.project_name
    Bucket      = each.value.name
  }
}

# S3 Bucket Policy for CloudFront (one per bucket with CloudFront)
resource "aws_s3_bucket_policy" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket if bucket.enable_cloudfront }

  bucket = aws_s3_bucket.buckets[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontServicePrincipal"
        Effect    = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.buckets[each.key].arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.buckets[each.key].arn
          }
        }
      }
    ]
  })

  depends_on = [aws_cloudfront_distribution.buckets]
}

# IAM Role for S3 Access
resource "aws_iam_role" "s3_access" {
  name = "${var.project_name}-${var.environment}-s3-access-role"

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

  tags = {
    Name        = "${var.project_name}-${var.environment}-s3-access-role"
    Environment = var.environment
    Project     = var.project_name
  }
}

# IAM Policy for S3 Access (access to all buckets)
resource "aws_iam_policy" "s3_access" {
  name        = "${var.project_name}-${var.environment}-s3-access-policy"
  description = "Policy for S3 bucket access"

  policy = jsonencode({ # tfsec:ignore:aws-iam-no-policy-wildcards
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                for bucket in aws_s3_bucket.buckets : bucket.arn
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                for bucket in aws_s3_bucket.buckets : "${bucket.arn}/*"
            ]
        }
    ]
})

  tags = {
    Name        = "${var.project_name}-${var.environment}-s3-access-policy"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Attach Policy to Role
resource "aws_iam_role_policy_attachment" "s3_access" {
  role       = aws_iam_role.s3_access.name
  policy_arn = aws_iam_policy.s3_access.arn
}

# Instance Profile for EC2
resource "aws_iam_instance_profile" "s3_access" {
  name = "${var.project_name}-${var.environment}-s3-access-profile"
  role = aws_iam_role.s3_access.name

  tags = {
    Name        = "${var.project_name}-${var.environment}-s3-access-profile"
    Environment = var.environment
    Project     = var.project_name
  }
}

# KMS Key for S3 Encryption
resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-s3-kms"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.project_name}-${var.environment}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# WAF Web ACL for CloudFront
resource "aws_wafv2_web_acl" "cloudfront" {
  name  = "${var.project_name}-${var.environment}-cloudfront-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # AWS Managed Rules
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled  = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRuleSetMetric"
      sampled_requests_enabled  = true
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSetMetric"
      sampled_requests_enabled  = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-${var.environment}-cloudfront-waf"
    sampled_requests_enabled  = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-cloudfront-waf"
    Environment = var.environment
    Project     = var.project_name
  }
}

# S3 Bucket for CloudFront Logs
resource "aws_s3_bucket" "cloudfront_logs" { # tfsec:ignore:aws-s3-enable-bucket-logging
  bucket = "${var.project_name}-${var.environment}-cloudfront-logs"

  tags = {
    Name        = "${var.project_name}-${var.environment}-cloudfront-logs"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_versioning" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets  = true
}

# S3 Bucket for Access Logs (centralized logging)
resource "aws_s3_bucket" "access_logs" { # tfsec:ignore:aws-s3-enable-bucket-logging
  bucket = "${var.project_name}-${var.environment}-access-logs"

  tags = {
    Name        = "${var.project_name}-${var.environment}-access-logs"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets  = true
}

# Enable access logging for all S3 buckets
resource "aws_s3_bucket_logging" "buckets" {
  for_each = { for bucket in local.all_buckets : bucket.name => bucket }

  bucket = aws_s3_bucket.buckets[each.key].id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/${each.value.name}/"
}