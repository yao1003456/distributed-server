#!/bin/bash

# User Data Script for AWS EC2

# Update and install dependencies
sudo yum update -y
sudo yum install -y docker git
sudo service docker start
sudo usermod -a -G docker ec2-user

# Install Nitro CLI
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne ec2-user
sudo usermod -aG docker ec2-user

# Configure allocator (Allocate memory/CPU for enclave)
# Adjust these values based on instance type and enclave requirements
sudo sed -i 's/memory_mib: .*/memory_mib: 4096/' /etc/nitro_enclaves/allocator.yaml
sudo sed -i 's/cpu_count: .*/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
sudo systemctl enable --now nitro-enclaves-allocator.service

# Run vsock-proxy for KMS on host (Map port 8001 to KMS)
# NOTE: This assumes the instance has an IAM role with KMS permissions
vsock-proxy 8001 kms.us-east-1.amazonaws.com 443 &

# Build and Run Enclave
# Need to build the EIF first
cd /home/ec2-user/app

# Ensure kmstool-enclave-cli placeholder exists so Docker build doesn't crash if missing
touch kmstool-enclave-cli
chmod +x kmstool-enclave-cli

docker build -t proxy-enclave -f Dockerfile.enclave .
nitro-cli build-enclave --docker-uri proxy-enclave:latest --output-file /home/ec2-user/proxy_enclave.eif

# Run Enclave
nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path /home/ec2-user/proxy_enclave.eif --enclave-cid 16

# Run EC2 Proxy (Host App)
# Create directory for enclave state persistence
mkdir -p /home/ec2-user/enclave_storage

cd /home/ec2-user/app

# Ensure .env.local and abi.json exist so Dockerfile doesn't crash
touch .env.local
touch abi.json

docker build -t proxy-ec2 -f Dockerfile.proxy .
docker run -d --net=host -v /home/ec2-user/enclave_storage:/app/enclave_storage -e KMS_KEY_ID="alias/my-enclave-key" proxy-ec2
