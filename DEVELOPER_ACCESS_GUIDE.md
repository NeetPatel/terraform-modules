# 🔐 **DEVELOPER READONLY ACCESS GUIDE**

## **📋 Overview**

This guide provides comprehensive instructions for setting up and managing readonly AWS access for your developer team. The solution follows AWS security best practices with IP restrictions, least privilege access, and comprehensive monitoring.

---

## **🎯 What Developers Can Access**

### **✅ Allowed Services (Readonly)**
- **EKS Cluster**: View cluster status, node groups, add-ons, and logs
- **Aurora Database**: View database configuration, metrics, and logs
- **S3 Buckets**: List and download objects from all project buckets
- **ECR Repositories**: View and pull container images
- **EC2 Instances**: View instance details, security groups, and logs
- **CloudWatch**: View logs, metrics, and dashboards
- **Route53**: View DNS records and hosted zones

### **❌ Restricted Actions**
- **No Write Operations**: Cannot create, modify, or delete resources
- **No Administrative Access**: Cannot change configurations
- **No Secret Access**: Cannot view sensitive data or credentials
- **IP Restricted**: Only accessible from approved IP ranges

---

## **🛡️ Security Features**

### **1. IP Address Restrictions**
All developer access is restricted to specific IP ranges:
- **IndiaNIC VPN**: `202.131.107.130/32`
- **IndiaNIC VPN**: `202.131.110.138/32`

### **2. Least Privilege Access**
- **Readonly Policies**: Only view permissions granted
- **Service-Specific**: Access limited to project resources only
- **Time-Based**: Access can be revoked at any time

### **3. Comprehensive Monitoring**
- **CloudTrail Logging**: All API calls logged
- **Security Hub**: Centralized security monitoring
- **GuardDuty**: Threat detection and analysis

---

## **👥 User Management**

### **Developer Groups**
The system creates three IAM groups:
1. **`devops-test-pre-prod-developers`**: General developers
2. **`devops-test-pre-prod-devops-team`**: DevOps engineers
3. **`devops-test-pre-prod-qa-team`**: QA engineers

### **Developer Users**
Current configured users:
- `john.doe`
- `jane.smith`
- `mike.wilson`
- `sarah.johnson`

---

## **🚀 Setup Instructions**

### **Step 1: Deploy the Infrastructure**
```bash
# Navigate to your Terraform directory
cd /home/indianic/Desktop/indianic/terrform

# Initialize Terraform
terraform init

# Plan the deployment
terraform plan

# Apply the configuration
terraform apply
```

### **Step 2: Configure AWS CLI for Developers**
Each developer needs to configure their AWS CLI:

```bash
# Install AWS CLI (if not already installed)
pip install awscli

# Configure AWS CLI
aws configure
```

**Required Information:**
- **Access Key ID**: Provided by AWS administrator
- **Secret Access Key**: Provided by AWS administrator
- **Default Region**: `us-east-1`
- **Output Format**: `json`

### **Step 3: Test Access**
Developers can test their access with these commands:

```bash
# Test EKS access
aws eks describe-cluster --name devops-test-pre-prod-eks

# Test S3 access
aws s3 ls s3://devops-test-pre-prod-static-assets

# Test Aurora access
aws rds describe-db-clusters --db-cluster-identifier devops-test-pre-prod-aurora-cluster

# Test ECR access
aws ecr describe-repositories
```

---

## **📊 Service-Specific Access**

### **EKS Cluster Access**
```bash
# View cluster information
aws eks describe-cluster --name devops-test-pre-prod-eks

# List node groups
aws eks list-nodegroups --cluster-name devops-test-pre-prod-eks

# View cluster logs
aws logs describe-log-groups --log-group-name-prefix "/aws/eks/devops-test-pre-prod-eks"

# Access Kubernetes API (if kubectl is configured)
kubectl get nodes
kubectl get pods --all-namespaces
```

### **Aurora Database Access**
```bash
# View cluster details
aws rds describe-db-clusters --db-cluster-identifier devops-test-pre-prod-aurora-cluster

# View cluster instances
aws rds describe-db-instances --db-instance-identifier devops-test-pre-prod-aurora-instance-1

# View cluster snapshots
aws rds describe-db-cluster-snapshots --db-cluster-identifier devops-test-pre-prod-aurora-cluster
```

### **S3 Bucket Access**
```bash
# List all project buckets
aws s3 ls | grep devops-test-pre-prod

# List objects in a specific bucket
aws s3 ls s3://devops-test-pre-prod-static-assets

# Download an object (readonly)
aws s3 cp s3://devops-test-pre-prod-static-assets/example.txt ./example.txt
```

### **ECR Repository Access**
```bash
# List repositories
aws ecr describe-repositories

# List images in a repository
aws ecr list-images --repository-name api

# Pull an image (if Docker is configured)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/api:latest
```

### **CloudWatch Logs Access**
```bash
# List log groups
aws logs describe-log-groups --log-group-name-prefix "/aws"

# View log streams
aws logs describe-log-streams --log-group-name "/aws/eks/devops-test-pre-prod-eks/cluster"

# Get log events
aws logs get-log-events --log-group-name "/aws/eks/devops-test-pre-prod-eks/cluster" --log-stream-name "stream-name"
```

---

## **🔧 Advanced Usage**

### **Kubectl Configuration for EKS**
To access the EKS cluster with kubectl:

```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name devops-test-pre-prod-eks

# Verify access
kubectl get nodes
kubectl get namespaces
kubectl get pods --all-namespaces
```

### **Docker Configuration for ECR**
To pull images from ECR:

```bash
# Get login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Pull images
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/api:latest
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/frontend:latest
```

---

## **📈 Monitoring & Troubleshooting**

### **Access Logs**
All developer access is logged in CloudTrail:
```bash
# View recent API calls
aws logs filter-log-events --log-group-name "/aws/cloudtrail/devops-test-pre-prod" --start-time $(date -d '1 hour ago' +%s)000
```

### **Common Issues**

#### **1. Access Denied Errors**
**Cause**: IP address not in allowed range
**Solution**: Ensure you're connecting from an approved IP address

#### **2. Resource Not Found**
**Cause**: Resource doesn't exist or wrong identifier
**Solution**: Verify resource names and identifiers

#### **3. Permission Denied**
**Cause**: Insufficient permissions
**Solution**: Contact administrator to verify group membership

### **Security Monitoring**
- **GuardDuty**: Monitors for suspicious activity
- **Security Hub**: Centralized security findings
- **CloudTrail**: API call audit trail
- **VPC Flow Logs**: Network traffic analysis

---

## **🔄 User Management**

### **Adding New Developers**
1. **Add to terraform.tfvars**:
```hcl
developer_users = [
  "john.doe",
  "jane.smith", 
  "mike.wilson",
  "sarah.johnson",
  "new.developer"  # Add new user here
]
```

2. **Apply Terraform**:
```bash
terraform plan
terraform apply
```

3. **Provide AWS Credentials**:
   - Generate access keys in AWS Console
   - Provide to developer securely

### **Removing Developers**
1. **Remove from terraform.tfvars**
2. **Apply Terraform**
3. **Revoke AWS credentials** in AWS Console

### **Changing IP Restrictions**
1. **Update terraform.tfvars**:
```hcl
developer_allowed_ip_ranges = [
  "202.131.107.130/32",
  "202.131.110.138/32",
  "new.office.ip/32"  # Add new IP range
]
```

2. **Apply Terraform**

---

## **📋 Best Practices**

### **For Developers**
- ✅ **Use MFA**: Enable multi-factor authentication
- ✅ **Secure Credentials**: Never share access keys
- ✅ **Regular Rotation**: Rotate access keys regularly
- ✅ **VPN Access**: Always use VPN when accessing AWS
- ✅ **Monitor Usage**: Check CloudTrail logs regularly

### **For Administrators**
- ✅ **Regular Audits**: Review access permissions quarterly
- ✅ **Principle of Least Privilege**: Grant minimum required access
- ✅ **Monitor Access**: Use Security Hub and GuardDuty
- ✅ **Document Changes**: Track all permission changes
- ✅ **Incident Response**: Have a plan for security incidents

---

## **🚨 Security Incident Response**

### **If Credentials Are Compromised**
1. **Immediately revoke** access keys in AWS Console
2. **Generate new credentials** for affected users
3. **Review CloudTrail logs** for suspicious activity
4. **Update Security Hub** with incident details
5. **Notify team** of security measures taken

### **If Unauthorized Access Detected**
1. **Block IP addresses** in security groups
2. **Revoke user access** immediately
3. **Investigate** using CloudTrail and GuardDuty
4. **Document findings** in Security Hub
5. **Implement additional controls** as needed

---

## **📞 Support & Contact**

### **Technical Issues**
- **AWS Support**: Use AWS Support Center
- **Internal Team**: Contact DevOps team
- **Documentation**: Refer to AWS documentation

### **Access Requests**
- **New Users**: Contact AWS administrator
- **Permission Changes**: Submit through change management
- **Emergency Access**: Follow incident response procedures

---

## **✅ Compliance & Audit**

### **Audit Trail**
- **CloudTrail**: Complete API call history
- **Security Hub**: Centralized security findings
- **GuardDuty**: Threat detection results
- **VPC Flow Logs**: Network traffic analysis

### **Compliance Standards**
- ✅ **SOC 2**: Security controls implemented
- ✅ **ISO 27001**: Information security management
- ✅ **PCI DSS**: Payment card industry standards
- ✅ **GDPR**: Data protection regulations

---

**🎯 This readonly access solution provides secure, monitored, and compliant access for your developer team while maintaining the highest security standards!**
