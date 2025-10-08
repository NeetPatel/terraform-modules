#!/bin/bash
/etc/eks/bootstrap.sh ${cluster_name}

# Configure kubelet for Karpenter
echo "KUBELET_EXTRA_ARGS='--node-labels=karpenter.sh/provisioner-name=default'" >> /etc/eks/bootstrap.sh

# Install Karpenter node termination handler
curl -fsSL https://karpenter.sh/v0.37.0/getting-started/getting-started-with-eksctl/termination-handler.yaml | kubectl apply -f -
