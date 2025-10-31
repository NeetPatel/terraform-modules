output "cluster_id" {
  description = "ID of the Aurora PostgreSQL cluster"
  value       = aws_rds_cluster.aurora.id
}

output "cluster_arn" {
  description = "ARN of the Aurora PostgreSQL cluster"
  value       = aws_rds_cluster.aurora.arn
}

output "cluster_endpoint" {
  description = "Endpoint of the Aurora PostgreSQL cluster"
  value       = aws_rds_cluster.aurora.endpoint
}

output "cluster_reader_endpoint" {
  description = "Reader endpoint of the Aurora PostgreSQL cluster"
  value       = aws_rds_cluster.aurora.reader_endpoint
}

output "cluster_port" {
  description = "Port of the Aurora PostgreSQL cluster"
  value       = aws_rds_cluster.aurora.port
}

output "cluster_database_name" {
  description = "Name of the Aurora PostgreSQL database"
  value       = aws_rds_cluster.aurora.database_name
}

output "cluster_master_username" {
  description = "Master username of the Aurora PostgreSQL cluster"
  value       = aws_rds_cluster.aurora.master_username
}

output "security_group_id" {
  description = "ID of the Aurora PostgreSQL security group"
  value       = aws_security_group.aurora.id
}

output "subnet_group_name" {
  description = "Name of the Aurora PostgreSQL subnet group"
  value       = aws_db_subnet_group.aurora.name
}

output "credentials_secret_arn" {
  description = "ARN of the secret containing Aurora PostgreSQL credentials"
  value       = aws_secretsmanager_secret.aurora_credentials.arn
  sensitive   = true
}

output "credentials_secret_name" {
  description = "Name of the secret containing Aurora PostgreSQL credentials"
  value       = aws_secretsmanager_secret.aurora_credentials.name
}

output "connection_command" {
  description = "PostgreSQL connection command"
  value       = "psql -h ${aws_rds_cluster.aurora.endpoint} -p ${aws_rds_cluster.aurora.port} -U ${var.master_username} -d ${var.database_name}"
  sensitive   = true
}

