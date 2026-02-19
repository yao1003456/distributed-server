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

# Run vsock-proxy for KMS on host (Map port 8000 to KMS)
# NOTE: This assumes the instance has an IAM role with KMS permissions
vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 &

# Build and Run Enclave
# NOTE: You need to transfer the EIF file to the instance or build it here.
# Assuming EIF is built and available at /home/ec2-user/proxy_enclave.eif

# Run Enclave
nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path /home/ec2-user/proxy_enclave.eif --enclave-cid 16

# Run EC2 Proxy (Host App)
# Assuming code is in /home/ec2-user/app
cd /home/ec2-user/app
docker build -t proxy-ec2 -f Dockerfile.proxy .
docker run -d --net=host -e KMS_KEY_ID="alias/my-key" proxy-ec2
