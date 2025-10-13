#!/bin/bash

# EC2 Jenkins Setup Script - Compact Version
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

log "Starting Jenkins Setup..."

# Update system
apt-get update -y
apt-get upgrade -y

# Install essentials
apt-get install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker ubuntu
systemctl start docker
systemctl enable docker

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf aws awscliv2.zip

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# Install Jenkins
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | gpg --dearmor -o /usr/share/keyrings/jenkins-keyring.asc
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/ | tee /etc/apt/sources.list.d/jenkins.list > /dev/null
apt-get update -y
apt-get install -y jenkins
usermod -aG docker jenkins
systemctl start jenkins
systemctl enable jenkins

# Install NGINX
apt-get install -y nginx

# Configure NGINX for Jenkins
cat > /etc/nginx/sites-available/jenkins << 'EOF'
upstream jenkins {
    server 127.0.0.1:8080 fail_timeout=0;
}

server {
    listen 80;
    server_name _;
    
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    client_max_body_size 100M;
    
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    proxy_connect_timeout 300;
    proxy_send_timeout 300;
    proxy_read_timeout 300;
    
    location / {
        proxy_pass http://jenkins;
        proxy_redirect http://jenkins/ /;
    }
    
    location /ws/ {
        proxy_pass http://jenkins;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable Jenkins site
ln -sf /etc/nginx/sites-available/jenkins /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl start nginx
systemctl enable nginx

# Jenkins security configuration
cat > /var/lib/jenkins/init.groovy.d/setup.groovy << 'EOF'
import jenkins.model.*
import hudson.security.*
import hudson.security.csrf.DefaultCrumbIssuer
import jenkins.security.s2m.AdminWhitelistRule

Jenkins.instance.getDescriptor("jenkins.CLI").get().setEnabled(false)
Jenkins.instance.setCrumbIssuer(new DefaultCrumbIssuer(true))
Jenkins.instance.getInjector().getInstance(AdminWhitelistRule.class).setMasterKillSwitch(false)
Jenkins.instance.save()
EOF

chown jenkins:jenkins /var/lib/jenkins/init.groovy.d/setup.groovy
systemctl restart jenkins

# Wait for services
sleep 30

# Verification
log "Verifying installations..."
systemctl is-active --quiet docker && log "✅ Docker running" || error "❌ Docker failed"
systemctl is-active --quiet jenkins && log "✅ Jenkins running" || error "❌ Jenkins failed"
systemctl is-active --quiet nginx && log "✅ NGINX running" || error "❌ NGINX failed"

# Get Jenkins password
JENKINS_PASSWORD=$(cat /var/lib/jenkins/secrets/initialAdminPassword 2>/dev/null || echo "Not available yet")
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Display summary
echo ""
echo "=========================================="
echo "🎉 JENKINS SETUP COMPLETE!"
echo "=========================================="
echo ""
echo "📋 Installation Summary:"
echo "  ✅ Docker: $(docker --version)"
echo "  ✅ AWS CLI: $(aws --version)"
echo "  ✅ kubectl: $(kubectl version --client --short)"
echo "  ✅ Jenkins: Running on port 8080"
echo "  ✅ NGINX: Reverse proxy on port 80"
echo ""
echo "🌐 Access Information:"
echo "  • Jenkins Direct: http://${PUBLIC_IP}:8080"
echo "  • Jenkins via NGINX: http://${PUBLIC_IP}"
echo ""
echo "🔑 Jenkins Initial Admin Password:"
echo "  ${JENKINS_PASSWORD}"
echo ""
echo "📝 Next Steps:"
echo "  1. Access Jenkins via web browser"
echo "  2. Complete initial setup wizard"
echo "  3. Install recommended plugins"
echo "  4. Create admin user"
echo "  5. Configure AWS credentials in Jenkins"
echo ""
echo "=========================================="

# Create completion marker
touch /var/log/jenkins-setup-complete
echo "Jenkins setup completed at $(date)" > /var/log/jenkins-setup-complete

log "Setup completed successfully!"