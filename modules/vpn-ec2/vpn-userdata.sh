#!/bin/bash

# OpenVPN Access Server Installation Script
# This script installs and configures OpenVPN Access Server

set -e

# Update system
apt-get update
apt-get upgrade -y

# Install required packages
apt-get install -y wget curl gnupg2 software-properties-common

# Add OpenVPN repository
wget -qO - https://as-repository.openvpn.net/as-repo-public.gpg | apt-key add -
echo "deb http://as-repository.openvpn.net/as/debian jammy main" > /etc/apt/sources.list.d/openvpn-as-repo.list

# Update package list
apt-get update

# Install OpenVPN Access Server
apt-get install -y openvpn-as

# Get the public IP address
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Configure OpenVPN
/usr/local/openvpn_as/scripts/sacli --key "host.name" --value "$PUBLIC_IP" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "vpn.server.routing.private_network.0" --value "10.0.0.0/8" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "vpn.server.routing.private_network.1" --value "172.16.0.0/12" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "vpn.server.routing.private_network.2" --value "192.168.0.0/16" ConfigPut

# Set admin password
/usr/local/openvpn_as/scripts/sacli --user "admin" --new_pass "${openvpn_password}" SetLocalPassword

# Configure client access
/usr/local/openvpn_as/scripts/sacli --key "vpn.client.routing.reroute_gw" --value "true" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "vpn.client.routing.reroute_dns" --value "true" ConfigPut

# Enable client access
/usr/local/openvpn_as/scripts/sacli --key "vpn.client.routing.reroute_gw" --value "true" ConfigPut

# Configure server settings
/usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.udp.port" --value "1194" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.tcp.port" --value "443" ConfigPut

# Enable web interface
/usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.port" --value "943" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "admin_ui.https.ip_address" --value "0.0.0.0" ConfigPut

# Configure client settings
/usr/local/openvpn_as/scripts/sacli --key "vpn.client.routing.reroute_gw" --value "true" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "vpn.client.routing.reroute_dns" --value "true" ConfigPut

# Start OpenVPN Access Server
/usr/local/openvpn_as/scripts/sacli start

# Create client user
/usr/local/openvpn_as/scripts/sacli --user "${vpn_client_name}" --new_pass "${openvpn_password}" SetLocalPassword

# Configure client profile
/usr/local/openvpn_as/scripts/sacli --user "${vpn_client_name}" --key "prop_autologin" --value "true" UserPropPut
/usr/local/openvpn_as/scripts/sacli --user "${vpn_client_name}" --key "prop_superuser" --value "false" UserPropPut

# Restart OpenVPN Access Server
/usr/local/openvpn_as/scripts/sacli restart

# Create startup script
cat > /etc/systemd/system/openvpn-as.service << EOF
[Unit]
Description=OpenVPN Access Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/openvpn_as/scripts/openvpnas
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
systemctl daemon-reload
systemctl enable openvpn-as
systemctl start openvpn-as

# Create connection info file
cat > /home/ubuntu/vpn-connection-info.txt << EOF
OpenVPN Access Server Connection Details
========================================

Server IP: $PUBLIC_IP
Admin URL: https://$PUBLIC_IP:943/admin
Client URL: https://$PUBLIC_IP:943/

Admin Credentials:
- Username: admin
- Password: ${openvpn_password}

Client Credentials:
- Username: ${vpn_client_name}
- Password: ${openvpn_password}

OpenVPN Ports:
- UDP: 1194
- TCP: 443

Web Interface Port: 943

To connect:
1. Download OpenVPN Connect client
2. Go to https://$PUBLIC_IP:943/
3. Login with client credentials
4. Download the connection profile
5. Import and connect

SSH Access:
- Host: $PUBLIC_IP
- Port: 22
- User: ubuntu
- Key: ${vpn_client_name}-key.pem
EOF

# Set proper permissions
chmod 600 /home/ubuntu/vpn-connection-info.txt

# Log completion
echo "OpenVPN Access Server installation completed successfully!" >> /var/log/vpn-install.log
echo "Server IP: $PUBLIC_IP" >> /var/log/vpn-install.log
echo "Admin URL: https://$PUBLIC_IP:943/admin" >> /var/log/vpn-install.log
