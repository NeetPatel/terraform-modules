# KMS Key for Aurora encryption
resource "aws_kms_key" "aurora" {
  description             = "KMS key for Aurora MySQL encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-kms"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_kms_alias" "aurora" {
  name          = "alias/${var.project_name}-${var.environment}-aurora"
  target_key_id = aws_kms_key.aurora.key_id
}

# Generate random password for Aurora
resource "random_password" "aurora_password" {
  length  = 32
  special = true
  upper   = true
  lower   = true
  numeric = true
}

# Store Aurora credentials in AWS Secrets Manager
resource "aws_secretsmanager_secret" "aurora_credentials" {
  name                    = "${var.project_name}-${var.environment}-aurora-credentials"
  description             = "Aurora MySQL credentials for ${var.project_name} ${var.environment}"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.aurora.arn

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-credentials"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_secretsmanager_secret_version" "aurora_credentials" {
  secret_id = aws_secretsmanager_secret.aurora_credentials.id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.aurora_password.result
    engine   = "mysql"
    host     = aws_rds_cluster.aurora.endpoint
    port     = aws_rds_cluster.aurora.port
    dbname   = var.database_name
  })
}

# DB Subnet Group
resource "aws_db_subnet_group" "aurora" {
  name       = "${var.project_name}-${var.environment}-aurora-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-subnet-group"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Security Group for Aurora
resource "aws_security_group" "aurora" {
  name_prefix = "${var.project_name}-${var.environment}-aurora-sg-"
  description = "Security group for Aurora MySQL cluster"
  vpc_id      = var.vpc_id

  # Allow MySQL access from EC2 instance only
  ingress {
    description     = "MySQL from EC2"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [var.ec2_security_group_id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-egress-sgr
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-sg"
    Environment = var.environment
    Project     = var.project_name
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Aurora Cluster
resource "aws_rds_cluster" "aurora" {
  cluster_identifier      = "${var.project_name}-${var.environment}-aurora-cluster"
  engine                  = "aurora-mysql"
  engine_mode             = "serverless"
  engine_version          = var.engine_version
  database_name           = var.database_name
  master_username         = var.master_username
  master_password         = random_password.aurora_password.result
  backup_retention_period = var.backup_retention_period
  deletion_protection     = var.deletion_protection
  skip_final_snapshot     = var.skip_final_snapshot
  storage_encrypted       = true
  kms_key_id             = aws_kms_key.aurora.arn
  vpc_security_group_ids = [aws_security_group.aurora.id]
  db_subnet_group_name   = aws_db_subnet_group.aurora.name

  # Serverless v2 scaling configuration
  serverlessv2_scaling_configuration {
    max_capacity = var.max_capacity
    min_capacity = var.min_capacity
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-cluster"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Aurora Cluster Instance (Serverless v2)
resource "aws_rds_cluster_instance" "aurora" {
  count              = var.instance_count
  identifier         = "${var.project_name}-${var.environment}-aurora-instance-${count.index + 1}"
  cluster_identifier  = aws_rds_cluster.aurora.id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.aurora.engine
  engine_version     = aws_rds_cluster.aurora.engine_version

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.aurora.arn
  performance_insights_retention_period = 7

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-instance-${count.index + 1}"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Parameter Group for Aurora
resource "aws_rds_cluster_parameter_group" "aurora" {
  family = "aurora-mysql8.0"
  name   = "${var.project_name}-${var.environment}-aurora-params"

  parameter {
    name  = "binlog_format"
    value = "ROW"
  }

  parameter {
    name  = "log_bin_trust_function_creators"
    value = "1"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-aurora-params"
    Environment = var.environment
    Project     = var.project_name
  }
}
