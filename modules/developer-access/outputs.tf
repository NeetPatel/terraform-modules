# Developer Access Module Outputs

output "developer_groups" {
  description = "List of developer IAM groups"
  value       = { for k, v in aws_iam_group.developers : k => v.name }
}

output "developer_users" {
  description = "List of developer IAM users"
  value       = { for k, v in aws_iam_user.developers : k => v.name }
}

output "policy_arns" {
  description = "ARNs of readonly policies"
  value = {
    eks_readonly        = aws_iam_policy.eks_readonly.arn
    aurora_readonly     = aws_iam_policy.aurora_readonly.arn
    s3_readonly         = aws_iam_policy.s3_readonly.arn
    ecr_readonly        = aws_iam_policy.ecr_readonly.arn
    cloudwatch_readonly = aws_iam_policy.cloudwatch_readonly.arn
    ec2_readonly        = aws_iam_policy.ec2_readonly.arn
    route53_readonly    = aws_iam_policy.route53_readonly.arn
  }
}

output "group_arns" {
  description = "ARNs of developer groups"
  value       = { for k, v in aws_iam_group.developers : k => v.arn }
}

output "user_arns" {
  description = "ARNs of developer users"
  value       = { for k, v in aws_iam_user.developers : k => v.arn }
}
