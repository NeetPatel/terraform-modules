#!/bin/bash
set -o xtrace

# EKS Node Group User Data Script
# This script configures the EKS node to join the cluster

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Configure kubelet
echo "KUBELET_EXTRA_ARGS='--node-labels=node.kubernetes.io/lifecycle=normal'" >> /etc/eksctl/kubelet.env

# Restart kubelet
systemctl restart kubelet

# Log completion
echo "EKS node configuration completed at $(date)" >> /var/log/eks-node-setup.log
