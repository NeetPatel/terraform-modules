output "repository_urls" {
  description = "URLs of the ECR repositories"
  value = {
    for repo_name, repo in aws_ecr_repository.repositories : repo_name => repo.repository_url
  }
}

output "repository_arns" {
  description = "ARNs of the ECR repositories"
  value = {
    for repo_name, repo in aws_ecr_repository.repositories : repo_name => repo.arn
  }
}

output "repository_names" {
  description = "Names of the ECR repositories"
  value = {
    for repo_name, repo in aws_ecr_repository.repositories : repo_name => repo.name
  }
}

output "repository_registry_ids" {
  description = "Registry IDs of the ECR repositories"
  value = {
    for repo_name, repo in aws_ecr_repository.repositories : repo_name => repo.registry_id
  }
}

output "login_command" {
  description = "AWS CLI command to login to ECR"
  value       = "aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
}

output "docker_push_commands" {
  description = "Docker push commands for each repository"
  value = {
    for repo_name, repo in aws_ecr_repository.repositories : repo_name => {
      tag_command   = "docker tag ${repo_name}:latest ${repo.repository_url}:latest"
      push_command  = "docker push ${repo.repository_url}:latest"
      pull_command  = "docker pull ${repo.repository_url}:latest"
    }
  }
}
