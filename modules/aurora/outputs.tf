output "cluster_id" {
  description = "ID of the Aurora cluster"
  value       = aws_rds_cluster.aurora.id
}

output "cluster_arn" {
  description = "ARN of the Aurora cluster"
  value       = aws_rds_cluster.aurora.arn
}

output "cluster_endpoint" {
  description = "Endpoint of the Aurora cluster"
  value       = aws_rds_cluster.aurora.endpoint
}

output "cluster_reader_endpoint" {
  description = "Reader endpoint of the Aurora cluster"
  value       = aws_rds_cluster.aurora.reader_endpoint
}

output "cluster_port" {
  description = "Port of the Aurora cluster"
  value       = aws_rds_cluster.aurora.port
}

output "cluster_database_name" {
  description = "Name of the Aurora database"
  value       = aws_rds_cluster.aurora.database_name
}

output "cluster_master_username" {
  description = "Master username of the Aurora cluster"
  value       = aws_rds_cluster.aurora.master_username
}

output "security_group_id" {
  description = "ID of the Aurora security group"
  value       = aws_security_group.aurora.id
}

output "subnet_group_name" {
  description = "Name of the Aurora subnet group"
  value       = aws_db_subnet_group.aurora.name
}

output "credentials_secret_arn" {
  description = "ARN of the secret containing Aurora credentials"
  value       = aws_secretsmanager_secret.aurora_credentials.arn
  sensitive   = true
}

output "credentials_secret_name" {
  description = "Name of the secret containing Aurora credentials"
  value       = aws_secretsmanager_secret.aurora_credentials.name
}

output "connection_command" {
  description = "MySQL connection command"
  value       = "mysql -h ${aws_rds_cluster.aurora.endpoint} -P ${aws_rds_cluster.aurora.port} -u ${var.master_username} -p${var.database_name}"
  sensitive   = true
}
