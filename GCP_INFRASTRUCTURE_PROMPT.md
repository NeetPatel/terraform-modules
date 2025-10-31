# GCP Enterprise DevOps Infrastructure - Terraform Prompt

Create a comprehensive Google Cloud Platform (GCP) infrastructure using Terraform that mirrors the enterprise-grade AWS infrastructure described below. The infrastructure should be production-ready with enterprise security controls, monitoring, and compliance features.

## 🏗️ **Infrastructure Requirements**

### **Core Components to Implement:**

1. **Compute Engine (VM) Instance**
   - Ubuntu 22.04 LTS with security hardening
   - Static external IP address
   - SSH key management with Google Secret Manager
   - Security-hardened firewall rules
   - Custom machine type configuration

2. **Virtual Private Cloud (VPC)**
   - Custom VPC with regional subnets
   - Public and private subnet configuration
   - Cloud NAT for private subnet internet access
   - Cloud Router for advanced routing
   - VPC Flow Logs enabled

3. **Cloud Storage (GCS)**
   - Multiple GCS buckets with environment-specific configurations
   - Cloud CDN integration for static content
   - Versioning and lifecycle policies
   - Uniform bucket-level access control
   - CORS configuration

4. **Cloud SQL (MySQL)**
   - Cloud SQL MySQL with high availability
   - Automated backups and point-in-time recovery
   - Private IP configuration
   - SSL/TLS encryption
   - Connection pooling

5. **Artifact Registry**
   - Multiple container repositories
   - Vulnerability scanning enabled
   - Lifecycle policies for image cleanup
   - IAM-based access control

6. **Google Kubernetes Engine (GKE)**
   - Regional GKE cluster with node pools
   - Workload Identity for secure pod authentication
   - Private cluster with authorized networks
   - Horizontal Pod Autoscaler (HPA)
   - Cluster Autoscaler
   - Google Cloud Load Balancer integration

7. **Cloud DNS**
   - Managed DNS zones
   - DNS records management
   - Health checks integration
   - Private DNS zones

8. **Cloud VPN**
   - Site-to-site VPN or Cloud VPN Gateway
   - Secure remote access configuration
   - VPN tunnel monitoring

9. **Advanced Security Controls**
   - Cloud Security Command Center (SCC)
   - Cloud Asset Inventory
   - Cloud Logging and Monitoring
   - Cloud IAM with least privilege
   - Cloud KMS for encryption key management
   - Binary Authorization for container security
   - Cloud Armor for DDoS protection and WAF

## 🔒 **Enterprise Security Requirements**

### **Security Rating Target: 9.5/10**

1. **Identity and Access Management**
   - Service accounts with minimal permissions
   - Workload Identity for GKE pods
   - IAM conditions for IP-based access
   - Organization policies for compliance

2. **Network Security**
   - Zero-trust network architecture
   - Private Google Access for private subnets
   - VPC Service Controls (if applicable)
   - Firewall rules with specific IP allowlists
   - Cloud Armor security policies

3. **Data Protection**
   - Encryption at rest using Cloud KMS
   - Encryption in transit with TLS 1.2+
   - Secret Manager for sensitive data
   - Cloud SQL encryption
   - GCS bucket encryption

4. **Monitoring and Compliance**
   - Cloud Logging with structured logs
   - Cloud Monitoring with custom dashboards
   - Security Command Center for threat detection
   - Cloud Asset Inventory for compliance
   - Cloud Audit Logs for API monitoring

5. **Container Security**
   - Binary Authorization for image verification
   - Vulnerability scanning in Artifact Registry
   - Pod Security Standards in GKE
   - Network policies for pod-to-pod communication

## 📁 **Required Project Structure**

```
gcp-infrastructure/
├── main.tf                    # Main Terraform configuration
├── variables.tf               # Input variables
├── outputs.tf                 # Output values
├── versions.tf                # Provider version constraints
├── terraform.tfvars           # Variables file
├── terraform.tfvars.example   # Example variables file
├── README.md                  # Documentation
└── modules/
    ├── compute/               # Compute Engine module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── network/               # VPC network module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── storage/               # GCS storage module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── database/              # Cloud SQL module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── artifact-registry/     # Artifact Registry module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── gke/                   # GKE cluster module
    │   ├── main.tf
    │   ├── variables.tf
    │   ├── outputs.tf
    │   └── versions.tf
    ├── dns/                   # Cloud DNS module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── vpn/                   # Cloud VPN module
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── security/              # Security controls module
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

## ⚙️ **Configuration Variables Required**

### **Core Variables:**
- `project_id`: GCP Project ID
- `region`: GCP region (e.g., "us-central1")
- `zone`: GCP zone (e.g., "us-central1-a")
- `project_name`: Project name for resource naming
- `environment`: Environment name (dev, staging, prod)

### **Compute Configuration:**
- `machine_type`: VM machine type
- `boot_disk_size`: Boot disk size in GB
- `boot_disk_type`: Boot disk type (pd-standard, pd-ssd)
- `allowed_ssh_cidrs`: CIDR blocks for SSH access
- `public_ssh_keys`: List of public SSH keys

### **Network Configuration:**
- `vpc_cidr`: CIDR block for VPC
- `public_subnet_cidrs`: Public subnet CIDRs
- `private_subnet_cidrs`: Private subnet CIDRs
- `enable_nat_gateway`: Enable Cloud NAT

### **Storage Configuration:**
- `gcs_bucket_names`: List of GCS bucket names
- `enable_cdn`: Enable Cloud CDN
- `enable_versioning`: Enable bucket versioning
- `lifecycle_rules`: Lifecycle management rules

### **Database Configuration:**
- `database_name`: Cloud SQL database name
- `database_version`: MySQL version
- `database_tier`: Database machine type
- `backup_enabled`: Enable automated backups
- `backup_retention_days`: Backup retention period

### **GKE Configuration:**
- `cluster_name`: GKE cluster name
- `cluster_version`: Kubernetes version
- `node_pools`: Node pool configurations
- `enable_private_nodes`: Enable private node pools
- `authorized_networks`: Authorized networks for cluster access
- `enable_workload_identity`: Enable Workload Identity

### **Security Configuration:**
- `enable_security_command_center`: Enable SCC
- `enable_binary_authorization`: Enable Binary Authorization
- `enable_cloud_armor`: Enable Cloud Armor
- `security_policies`: Cloud Armor security policies

## 🚀 **Implementation Requirements**

### **1. Provider Configuration**
```hcl
terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0"
    }
  }
}
```

### **2. Security Best Practices**
- Use least privilege IAM roles
- Enable audit logging for all services
- Implement network segmentation
- Use private Google Access
- Enable VPC Flow Logs
- Configure Cloud Armor policies
- Enable Binary Authorization
- Use Workload Identity for GKE

### **3. Monitoring and Logging**
- Structured logging with Cloud Logging
- Custom metrics with Cloud Monitoring
- Alerting policies for critical resources
- Security Command Center integration
- Cloud Asset Inventory for compliance

### **4. Cost Optimization**
- Use committed use discounts where applicable
- Implement proper resource tagging
- Use preemptible instances for non-critical workloads
- Configure proper lifecycle policies

## 📋 **Expected Outputs**

The infrastructure should provide outputs for:

1. **Compute Outputs:**
   - VM instance details
   - External IP addresses
   - SSH connection commands
   - Secret Manager secret ARNs

2. **Network Outputs:**
   - VPC network details
   - Subnet information
   - Cloud NAT gateway details
   - Firewall rule IDs

3. **Storage Outputs:**
   - GCS bucket names and URLs
   - Cloud CDN domain names
   - Storage bucket ARNs

4. **Database Outputs:**
   - Cloud SQL connection details
   - Database credentials secret ARN
   - Connection strings

5. **GKE Outputs:**
   - Cluster details and endpoints
   - Node pool information
   - kubectl configuration commands
   - Workload Identity details

6. **Security Outputs:**
   - Security Command Center details
   - Cloud Armor policy information
   - Binary Authorization policy details
   - Audit log configurations

## 🔧 **Advanced Features Required**

1. **Multi-Environment Support:**
   - Environment-specific configurations
   - Resource naming conventions
   - Environment-specific security policies

2. **Disaster Recovery:**
   - Cross-region backup configuration
   - Automated backup policies
   - Point-in-time recovery setup

3. **Compliance Features:**
   - SOC 2 Type II compliance ready
   - PCI DSS compliance support
   - HIPAA compliance features
   - ISO 27001 alignment

4. **Developer Experience:**
   - Easy deployment scripts
   - Comprehensive documentation
   - Troubleshooting guides
   - Cost estimation tools

## 📝 **Documentation Requirements**

Create comprehensive documentation including:

1. **README.md** with:
   - Architecture overview
   - Security features and ratings
   - Quick start guide
   - Configuration options
   - Troubleshooting section

2. **Security Documentation:**
   - Security controls implementation
   - Compliance features
   - Security best practices
   - Incident response procedures

3. **Operational Documentation:**
   - Monitoring and alerting setup
   - Backup and recovery procedures
   - Cost optimization guidelines
   - Maintenance procedures

## 🎯 **Success Criteria**

The GCP infrastructure should:

1. **Match AWS Feature Parity:**
   - Equivalent security controls
   - Similar monitoring capabilities
   - Comparable performance characteristics
   - Same compliance readiness

2. **Enterprise Readiness:**
   - Production-ready configuration
   - Scalable architecture
   - High availability setup
   - Disaster recovery capabilities

3. **Security Excellence:**
   - 9.5/10 security rating
   - Comprehensive threat protection
   - Zero-trust network architecture
   - Advanced monitoring and compliance

4. **Operational Excellence:**
   - Easy deployment and management
   - Comprehensive documentation
   - Troubleshooting guides
   - Cost optimization features

## 💡 **Additional Considerations**

1. **GCP-Specific Features:**
   - Leverage GCP's unique services
   - Use Google Cloud's AI/ML capabilities where applicable
   - Implement Google Cloud's networking advantages
   - Utilize GCP's global infrastructure

2. **Migration Considerations:**
   - Design for potential multi-cloud scenarios
   - Consider data migration strategies
   - Plan for application compatibility
   - Design for cost optimization

3. **Future-Proofing:**
   - Modular design for easy updates
   - Scalable architecture for growth
   - Flexible configuration options
   - Integration-ready design

This prompt should result in a comprehensive, enterprise-grade GCP infrastructure that matches the security, functionality, and operational excellence of the AWS infrastructure described in the original setup.
