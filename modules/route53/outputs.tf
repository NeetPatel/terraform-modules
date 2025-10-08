# Route53 Module Outputs

output "hosted_zone_ids" {
  description = "Map of hosted zone IDs"
  value = {
    for k, v in aws_route53_zone.zones : k => v.zone_id
  }
}

output "hosted_zone_names" {
  description = "Map of hosted zone names"
  value = {
    for k, v in aws_route53_zone.zones : k => v.name
  }
}

output "hosted_zone_name_servers" {
  description = "Map of hosted zone name servers"
  value = {
    for k, v in aws_route53_zone.zones : k => v.name_servers
  }
}

output "hosted_zone_arns" {
  description = "Map of hosted zone ARNs"
  value = {
    for k, v in aws_route53_zone.zones : k => v.arn
  }
}

output "dns_record_ids" {
  description = "Map of DNS record IDs"
  value = {
    for k, v in aws_route53_record.records : k => v.id
  }
}

output "health_check_ids" {
  description = "Map of health check IDs"
  value = {
    for k, v in aws_route53_health_check.health_checks : k => v.id
  }
}

output "health_check_arns" {
  description = "Map of health check ARNs"
  value = {
    for k, v in aws_route53_health_check.health_checks : k => v.arn
  }
}

output "name_servers" {
  description = "Name servers for all hosted zones"
  value = {
    for k, v in aws_route53_zone.zones : k => {
      domain_name = v.name
      name_servers = v.name_servers
      zone_id = v.zone_id
    }
  }
}

output "dns_commands" {
  description = "Commands to manage DNS"
  value = {
    list_hosted_zones = "aws route53 list-hosted-zones"
    get_hosted_zone = "aws route53 get-hosted-zone --id <zone-id>"
    list_resource_record_sets = "aws route53 list-resource-record-sets --hosted-zone-id <zone-id>"
    test_dns_resolution = "nslookup <domain-name>"
    check_name_servers = "dig NS <domain-name>"
  }
}
