# Security Module Outputs

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail"
  value       = aws_cloudtrail.main.name
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.main.id
}

output "security_hub_arn" {
  description = "ARN of the Security Hub"
  value       = aws_securityhub_account.main.arn
}

output "config_recorder_name" {
  description = "Name of the Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "acm_certificate_arn" {
  description = "ARN of the ACM certificate"
  value       = aws_acm_certificate.main.arn
}

output "acm_certificate_domain_validation_options" {
  description = "Domain validation options for ACM certificate"
  value       = aws_acm_certificate.main.domain_validation_options
}

output "vpc_flow_log_id" {
  description = "ID of the VPC flow log"
  value       = aws_flow_log.vpc_flow_log.id
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for VPC flow logs"
  value       = aws_cloudwatch_log_group.vpc_flow_log.name
}

output "security_commands" {
  description = "Commands to manage security services"
  value = {
    check_cloudtrail_status = "aws cloudtrail get-trail-status --name ${aws_cloudtrail.main.name}"
    check_guardduty_findings = "aws guardduty list-findings --detector-id ${aws_guardduty_detector.main.id}"
    check_security_hub_findings = "aws securityhub get-findings"
    check_config_status = "aws config describe-configuration-recorder-status --configuration-recorder-names ${aws_config_configuration_recorder.main.name}"
    check_waf_metrics = "aws wafv2 get-web-acl --scope REGIONAL --id ${aws_wafv2_web_acl.main.id}"
    check_certificate_status = "aws acm describe-certificate --certificate-arn ${aws_acm_certificate.main.arn}"
    check_flow_logs = "aws logs describe-log-streams --log-group-name ${aws_cloudwatch_log_group.vpc_flow_log.name}"
  }
}
