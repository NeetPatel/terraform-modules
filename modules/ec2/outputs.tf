output "private_key" {
  description = "Private key for EC2 instance (only if generated)"
  value       = length(var.public_ssh_keys) == 0 ? tls_private_key.ec2_key[0].private_key_pem : null
  sensitive   = true
}

output "key_name" {
  description = "Name of the primary AWS key pair"
  value = length(var.public_ssh_keys) > 0 ? aws_key_pair.ec2_keys[0].key_name : aws_key_pair.ec2_generated_key[0].key_name
}

output "all_key_names" {
  description = "Names of all AWS key pairs"
  value = length(var.public_ssh_keys) > 0 ? aws_key_pair.ec2_keys[*].key_name : [aws_key_pair.ec2_generated_key[0].key_name]
}

output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.ec2_instance.id
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.ec2_instance.public_ip
}

output "elastic_ip" {
  description = "Elastic IP address of the EC2 instance"
  value       = aws_eip.ec2_eip.public_ip
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.ec2_sg.id
}

output "instance_private_ip" {
  description = "Private IP address of the EC2 instance"
  value       = aws_instance.ec2_instance.private_ip
}

output "availability_zone" {
  description = "Availability zone of the EC2 instance"
  value       = aws_instance.ec2_instance.availability_zone
}

# Jenkins-related outputs
output "jenkins_url" {
  description = "Jenkins URL via NGINX reverse proxy"
  value       = "http://${aws_eip.ec2_eip.public_ip}"
}

output "jenkins_direct_url" {
  description = "Jenkins direct URL (port 8080)"
  value       = "http://${aws_eip.ec2_eip.public_ip}:8080"
}

output "jenkins_setup_complete" {
  description = "Jenkins setup completion status"
  value       = "Setup script deployed. Check /var/log/jenkins-setup-complete after instance startup."
}
