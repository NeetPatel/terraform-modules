# VPN EC2 Instance Module Outputs

output "vpn_instance_id" {
  description = "ID of the VPN EC2 instance"
  value       = aws_instance.vpn_server.id
}

output "vpn_instance_public_ip" {
  description = "Public IP of the VPN EC2 instance"
  value       = aws_instance.vpn_server.public_ip
}

output "vpn_elastic_ip" {
  description = "Elastic IP address of the VPN server"
  value       = aws_eip.vpn_eip.public_ip
}

output "vpn_elastic_ip_dns" {
  description = "Elastic IP DNS name"
  value       = aws_eip.vpn_eip.public_dns
}

output "vpn_security_group_id" {
  description = "Security group ID of the VPN server"
  value       = aws_security_group.vpn_sg.id
}

output "vpn_key_pair_name" {
  description = "Key pair name for VPN server"
  value       = aws_key_pair.vpn_key.key_name
}

output "vpn_ssh_private_key_secret_arn" {
  description = "ARN of the secret containing the VPN server private key"
  value       = aws_secretsmanager_secret.vpn_connection.arn
}

output "vpn_password_secret_arn" {
  description = "ARN of the secret containing the OpenVPN password"
  value       = aws_secretsmanager_secret.openvpn_password.arn
}

output "vpn_connection_secret_arn" {
  description = "ARN of the secret containing VPN connection details"
  value       = aws_secretsmanager_secret.vpn_connection.arn
}

output "vpn_admin_url" {
  description = "OpenVPN Access Server admin URL"
  value       = "https://${aws_eip.vpn_eip.public_ip}:943/admin"
}

output "vpn_client_url" {
  description = "OpenVPN Access Server client URL"
  value       = "https://${aws_eip.vpn_eip.public_ip}:943/"
}

output "vpn_ssh_connection_command" {
  description = "SSH connection command for VPN server"
  value       = "ssh -i vpn-key.pem ubuntu@${aws_eip.vpn_eip.public_ip}"
}

output "vpn_connection_info" {
  description = "VPN connection information"
  value = {
    server_ip     = aws_eip.vpn_eip.public_ip
    server_domain = aws_eip.vpn_eip.public_dns
    openvpn_port  = 1194
    admin_url     = "https://${aws_eip.vpn_eip.public_ip}:943/admin"
    client_url    = "https://${aws_eip.vpn_eip.public_ip}:943/"
    ssh_key       = aws_key_pair.vpn_key.key_name
  }
}

output "vpn_cloudwatch_log_group" {
  description = "CloudWatch log group for VPN server"
  value       = aws_cloudwatch_log_group.vpn_logs.name
}

output "vpn_cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN for VPN server"
  value       = aws_cloudwatch_log_group.vpn_logs.arn
}
