# EKS Module Outputs

# EKS Cluster Outputs
output "cluster_id" {
  description = "ID of the EKS cluster"
  value       = aws_eks_cluster.cluster.id
}

output "cluster_arn" {
  description = "ARN of the EKS cluster"
  value       = aws_eks_cluster.cluster.arn
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = aws_eks_cluster.cluster.name
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = aws_eks_cluster.cluster.endpoint
}

output "cluster_version" {
  description = "Kubernetes version of the EKS cluster"
  value       = aws_eks_cluster.cluster.version
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_eks_cluster.cluster.vpc_config[0].cluster_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = aws_eks_cluster.cluster.certificate_authority[0].data
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

output "cluster_oidc_provider_arn" {
  description = "ARN of the OIDC provider"
  value       = var.enable_alb ? aws_iam_openid_connect_provider.eks[0].arn : null
}

# Node Group Outputs
output "node_groups" {
  description = "Map of EKS node groups"
  value = {
    for k, v in aws_eks_node_group.node_groups : k => {
      arn           = v.arn
      status        = v.status
      capacity_type = v.capacity_type
      instance_types = v.instance_types
      scaling_config = v.scaling_config
      labels        = v.labels
    }
  }
}

output "node_group_arns" {
  description = "ARNs of the EKS node groups"
  value       = { for k, v in aws_eks_node_group.node_groups : k => v.arn }
}

# IAM Role Outputs
output "cluster_iam_role_arn" {
  description = "ARN of the EKS cluster IAM role"
  value       = aws_iam_role.eks_cluster_role.arn
}

output "node_group_iam_role_arn" {
  description = "ARN of the EKS node group IAM role"
  value       = aws_iam_role.eks_node_group_role.arn
}

output "aws_load_balancer_controller_role_arn" {
  description = "ARN of the AWS Load Balancer Controller IAM role"
  value       = var.enable_alb ? aws_iam_role.aws_load_balancer_controller[0].arn : null
}

# ALB Outputs
output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = var.enable_alb ? aws_lb.alb[0].arn : null
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = var.enable_alb ? aws_lb.alb[0].dns_name : null
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = var.enable_alb ? aws_lb.alb[0].zone_id : null
}

output "alb_hosted_zone_id" {
  description = "Hosted zone ID of the Application Load Balancer"
  value       = var.enable_alb ? aws_lb.alb[0].zone_id : null
}

output "alb_security_group_id" {
  description = "Security group ID of the Application Load Balancer"
  value       = var.enable_alb ? aws_security_group.alb[0].id : null
}

# Target Group Outputs
output "target_groups" {
  description = "Map of ALB target groups"
  value = var.enable_alb ? {
    for k, v in aws_lb_target_group.target_groups : k => {
      arn                = v.arn
      name               = v.name
      port               = v.port
      protocol           = v.protocol
      target_type        = v.target_type
      health_check_path  = v.health_check[0].path
      health_check_port  = v.health_check[0].port
      health_check_protocol = v.health_check[0].protocol
    }
  } : {}
}

output "target_group_arns" {
  description = "ARNs of the ALB target groups"
  value       = var.enable_alb ? { for k, v in aws_lb_target_group.target_groups : k => v.arn } : {}
}

# Listener Outputs
output "listeners" {
  description = "Map of ALB listeners"
  value = var.enable_alb ? {
    for k, v in aws_lb_listener.listeners : k => {
      arn      = v.arn
      port     = v.port
      protocol = v.protocol
    }
  } : {}
}

output "listener_arns" {
  description = "ARNs of the ALB listeners"
  value       = var.enable_alb ? { for k, v in aws_lb_listener.listeners : k => v.arn } : {}
}

# EKS Add-ons Outputs
output "addons" {
  description = "Map of EKS add-ons"
  value = {
    vpc_cni = {
      arn     = aws_eks_addon.vpc_cni.arn
      version = aws_eks_addon.vpc_cni.addon_version
    }
    coredns = {
      arn     = aws_eks_addon.coredns.arn
      version = aws_eks_addon.coredns.addon_version
    }
    kube_proxy = {
      arn     = aws_eks_addon.kube_proxy.arn
      version = aws_eks_addon.kube_proxy.addon_version
    }
    ebs_csi_driver = {
      arn     = aws_eks_addon.ebs_csi_driver.arn
      version = aws_eks_addon.ebs_csi_driver.addon_version
    }
  }
}

# Kubectl Configuration
output "kubectl_config_command" {
  description = "Command to configure kubectl for the EKS cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.cluster.name}"
}

output "kubectl_config_file" {
  description = "Path to the kubectl config file"
  value       = "~/.kube/config"
}

# Cluster Access Commands
output "cluster_access_commands" {
  description = "Commands to access the EKS cluster"
  value = {
    update_kubeconfig = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.cluster.name}"
    get_nodes        = "kubectl get nodes"
    get_pods         = "kubectl get pods --all-namespaces"
    get_services     = "kubectl get services --all-namespaces"
    get_ingress      = "kubectl get ingress --all-namespaces"
  }
}

# ALB Access Information
output "alb_access_info" {
  description = "ALB access information"
  value = var.enable_alb ? {
    dns_name = aws_lb.alb[0].dns_name
    url      = "http://${aws_lb.alb[0].dns_name}"
    https_url = var.alb_listeners["https"] != null ? "https://${aws_lb.alb[0].dns_name}" : null
  } : null
}

# WAF Association Output
output "waf_web_acl_association_id" {
  description = "ID of the WAF Web ACL association with ALB"
  value       = var.enable_alb && var.enable_waf && var.waf_web_acl_arn != null ? aws_wafv2_web_acl_association.alb[0].id : null
}

# CloudWatch Log Group Output
output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for EKS cluster"
  value       = aws_cloudwatch_log_group.cluster_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for EKS cluster"
  value       = aws_cloudwatch_log_group.cluster_logs.arn
}

# Karpenter Outputs
output "karpenter_iam_role_arn" {
  description = "ARN of the Karpenter IAM role"
  value       = var.enable_karpenter ? aws_iam_role.karpenter[0].arn : null
}

output "karpenter_instance_profile_name" {
  description = "Name of the Karpenter instance profile"
  value       = var.enable_karpenter ? aws_iam_instance_profile.karpenter[0].name : null
}

output "karpenter_sqs_queue_arn" {
  description = "ARN of the Karpenter SQS queue"
  value       = var.enable_karpenter ? aws_sqs_queue.karpenter[0].arn : null
}

output "karpenter_sqs_queue_url" {
  description = "URL of the Karpenter SQS queue"
  value       = var.enable_karpenter ? aws_sqs_queue.karpenter[0].id : null
}

output "karpenter_eventbridge_rule_arn" {
  description = "ARN of the Karpenter EventBridge rule"
  value       = var.enable_karpenter ? aws_cloudwatch_event_rule.karpenter[0].arn : null
}

output "karpenter_nodepools" {
  description = "Map of Karpenter NodePools"
  value = var.enable_karpenter ? {
    for k, v in var.karpenter_nodepools : k => {
      name           = k
      instance_types = v.instance_types
      capacity_type  = v.capacity_type
      min_capacity   = v.min_capacity
      max_capacity   = v.max_capacity
      labels         = v.labels
      taints         = v.taints
    }
  } : {}
}

output "karpenter_helm_release_name" {
  description = "Name of the Karpenter Helm release"
  value       = var.enable_karpenter ? helm_release.karpenter[0].name : null
}

output "karpenter_helm_release_version" {
  description = "Version of the Karpenter Helm release"
  value       = var.enable_karpenter ? helm_release.karpenter[0].version : null
}

output "karpenter_helm_release_namespace" {
  description = "Namespace of the Karpenter Helm release"
  value       = var.enable_karpenter ? helm_release.karpenter[0].namespace : null
}

# Karpenter Commands
output "karpenter_commands" {
  description = "Commands to manage Karpenter"
  value = var.enable_karpenter ? {
    check_karpenter_status = "kubectl get pods -n karpenter"
    check_nodepools = "kubectl get nodepools"
    check_nodes = "kubectl get nodes -l karpenter.sh/provisioner-name"
    check_karpenter_logs = "kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter"
  } : null
}

# External DNS Outputs
output "external_dns_iam_role_arn" {
  description = "ARN of the External DNS IAM role"
  value       = var.enable_external_dns ? aws_iam_role.external_dns[0].arn : null
}

output "external_dns_helm_release_name" {
  description = "Name of the External DNS Helm release"
  value       = var.enable_external_dns ? helm_release.external_dns[0].name : null
}

output "external_dns_helm_release_version" {
  description = "Version of the External DNS Helm release"
  value       = var.enable_external_dns ? helm_release.external_dns[0].version : null
}

output "external_dns_helm_release_namespace" {
  description = "Namespace of the External DNS Helm release"
  value       = var.enable_external_dns ? helm_release.external_dns[0].namespace : null
}

output "external_dns_commands" {
  description = "Commands to manage External DNS"
  value = var.enable_external_dns ? {
    check_external_dns_status = "kubectl get pods -n external-dns"
    check_external_dns_logs = "kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns"
    check_dns_records = "kubectl get ingress --all-namespaces -o wide"
    check_external_dns_config = "kubectl get configmap -n external-dns external-dns -o yaml"
  } : null
}
