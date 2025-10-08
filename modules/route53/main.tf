# Route53 Module
# This module creates Route53 hosted zones for domain management

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Route53 Hosted Zones
resource "aws_route53_zone" "zones" {
  for_each = var.hosted_zones

  name = each.value.domain_name
  comment = each.value.comment != "" ? each.value.comment : "Managed by Terraform for ${var.project_name}-${var.environment}"

  tags = merge(local.common_tags, {
    Name = each.key
    Domain = each.value.domain_name
  })
}

# Route53 Records (optional)
resource "aws_route53_record" "records" {
  for_each = var.dns_records

  zone_id = aws_route53_zone.zones[each.value.zone_key].zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = each.value.ttl

  records = each.value.records
}

# Route53 Health Checks (optional)
resource "aws_route53_health_check" "health_checks" {
  for_each = var.health_checks

  fqdn                            = each.value.fqdn
  port                            = each.value.port
  type                            = each.value.type
  resource_path                   = each.value.resource_path
  failure_threshold               = each.value.failure_threshold
  request_interval                = each.value.request_interval
  cloudwatch_alarm_region         = each.value.cloudwatch_alarm_region
  cloudwatch_alarm_name           = each.value.cloudwatch_alarm_name
  insufficient_data_health_status = each.value.insufficient_data_health_status

  tags = merge(local.common_tags, {
    Name = each.key
  })
}

# Local values
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Module      = "route53"
  }
}
