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
      sse_algorithm = "AES256"
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

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
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

  policy = jsonencode({
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