#!/bin/bash

# deploy_aws.sh
# Automates the setup of the EC2 Host and Nitro Enclave for the Proxy Server

set -e

echo "=========================================="
echo "Starting AWS Deployment Setup..."
echo "=========================================="

# 1. System Updates and Dependencies
echo "[1/6] Updating system and installing dependencies..."
sudo dnf update -y
sudo dnf install -y gcc git python3-pip

# 2. Install and Configure Docker
echo "[2/6] Installing Docker..."
sudo dnf install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# 3. Install and Configure Redis
echo "[3/6] Starting Redis container..."
sudo docker run -d -p 6379:6379 --name redis --restart always redis

# 4. Install and Configure AWS Nitro Enclaves CLI
echo "[4/6] Installing Nitro Enclaves CLI..."
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start nitro-enclaves-allocator.service

# Configure allocator (Assumes c6a.xlarge - 4 vCPUs. Allocating 2 vCPUs and 1024MB RAM to Enclave)
echo "[*] Configuring Nitro Enclave allocator..."
sudo sed -i 's/memory_mib: .*/memory_mib: 1024/' /etc/nitro_enclaves/allocator.yaml
sudo sed -i 's/cpu_count: .*/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
sudo systemctl restart nitro-enclaves-allocator.service

# 5. Build and Run the Enclave Image
echo "[5/6] Building and starting the Enclave..."
# Build the docker image locally first
sudo docker build -t proxy-enclave-image -f Dockerfile.enclave .

# Convert Docker image to Enclave Image Format (EIF)
nitro-cli build-enclave --docker-uri proxy-enclave-image:latest --output-file proxy_enclave.eif

# Terminate any existing enclaves
ENCLAVE_ID=$(nitro-cli describe-enclaves | grep -oP '"EnclaveID": "\K[^"]+')
if [ -n "$ENCLAVE_ID" ]; then
    echo "Terminating existing enclave $ENCLAVE_ID..."
    nitro-cli terminate-enclave --enclave-id $ENCLAVE_ID
fi

# Run the enclave
nitro-cli run-enclave --cpu-count 2 --memory 1024 --eif-path proxy_enclave.eif --enclave-cid 16

# 6. Setup EC2 Proxy Service
echo "[6/6] Setting up Proxy EC2 Service..."
pip3 install -r requirements.txt gunicorn uvicorn

# Setup systemd service (assuming service file is present)
sudo cp proxy_ec2.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable proxy_ec2
sudo systemctl start proxy_ec2
sudo systemctl status proxy_ec2 --no-pager

echo "=========================================="
echo "Deployment Setup Complete!"
echo "Check Enclave Status: nitro-cli describe-enclaves"
echo "Check EC2 Proxy Logs: sudo journalctl -u proxy_ec2 -f"
echo "=========================================="
