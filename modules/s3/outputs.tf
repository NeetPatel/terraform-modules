# Bucket outputs
output "bucket_ids" {
  description = "IDs of the S3 buckets"
  value = {
    for bucket_name, bucket in aws_s3_bucket.buckets : bucket_name => bucket.id
  }
}

output "bucket_arns" {
  description = "ARNs of the S3 buckets"
  value = {
    for bucket_name, bucket in aws_s3_bucket.buckets : bucket_name => bucket.arn
  }
}

output "bucket_domain_names" {
  description = "Domain names of the S3 buckets"
  value = {
    for bucket_name, bucket in aws_s3_bucket.buckets : bucket_name => bucket.bucket_domain_name
  }
}

output "bucket_regional_domain_names" {
  description = "Regional domain names of the S3 buckets"
  value = {
    for bucket_name, bucket in aws_s3_bucket.buckets : bucket_name => bucket.bucket_regional_domain_name
  }
}

# CloudFront outputs
output "cloudfront_distribution_ids" {
  description = "IDs of the CloudFront distributions"
  value = {
    for bucket_name, distribution in aws_cloudfront_distribution.buckets : bucket_name => distribution.id
  }
}

output "cloudfront_domain_names" {
  description = "Domain names of the CloudFront distributions"
  value = {
    for bucket_name, distribution in aws_cloudfront_distribution.buckets : bucket_name => distribution.domain_name
  }
}

output "cloudfront_arns" {
  description = "ARNs of the CloudFront distributions"
  value = {
    for bucket_name, distribution in aws_cloudfront_distribution.buckets : bucket_name => distribution.arn
  }
}

output "cloudfront_urls" {
  description = "URLs of the CloudFront distributions"
  value = {
    for bucket_name, distribution in aws_cloudfront_distribution.buckets : bucket_name => "https://${distribution.domain_name}"
  }
}

# IAM outputs
output "iam_role_arn" {
  description = "ARN of the IAM role for S3 access"
  value       = aws_iam_role.s3_access.arn
}

output "iam_role_name" {
  description = "Name of the IAM role for S3 access"
  value       = aws_iam_role.s3_access.name
}

output "instance_profile_name" {
  description = "Name of the IAM instance profile"
  value       = aws_iam_instance_profile.s3_access.name
}

output "instance_profile_arn" {
  description = "ARN of the IAM instance profile"
  value       = aws_iam_instance_profile.s3_access.arn
}

# Legacy outputs for backward compatibility (first bucket only)
output "bucket_id" {
  description = "ID of the first S3 bucket (legacy)"
  value       = length(aws_s3_bucket.buckets) > 0 ? values(aws_s3_bucket.buckets)[0].id : null
}

output "bucket_arn" {
  description = "ARN of the first S3 bucket (legacy)"
  value       = length(aws_s3_bucket.buckets) > 0 ? values(aws_s3_bucket.buckets)[0].arn : null
}

output "cloudfront_domain_name" {
  description = "Domain name of the first CloudFront distribution (legacy)"
  value       = length(aws_cloudfront_distribution.buckets) > 0 ? values(aws_cloudfront_distribution.buckets)[0].domain_name : null
}

output "cloudfront_url" {
  description = "URL of the first CloudFront distribution (legacy)"
  value       = length(aws_cloudfront_distribution.buckets) > 0 ? "https://${values(aws_cloudfront_distribution.buckets)[0].domain_name}" : null
}