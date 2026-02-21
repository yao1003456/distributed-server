#!/bin/bash
set -e

# Configuration
IMAGE_NAME="proxy-enclave"
EIF_NAME="proxy-enclave.eif"
DOCKERFILE="Dockerfile.enclave"
CPU_COUNT=2
MEMORY_MB=2048
ENCLAVE_CID=16

echo "--- Building Docker Image: $IMAGE_NAME ---"
docker build -f $DOCKERFILE -t $IMAGE_NAME .

echo "--- Building Nitro Enclave Image (EIF): $EIF_NAME ---"
# Note: nitro-cli requires root or 'ne' group membership
nitro-cli build-enclave --docker-uri $IMAGE_NAME:latest --output-file $EIF_NAME

echo "--- EIF Build Complete! ---"
echo "IMPORTANT: Save the PCR0 value printed above for your KMS Key Policy condition."

echo ""
echo "Command to run the enclave:"
echo "nitro-cli run-enclave --cpu-count $CPU_COUNT --memory $MEMORY_MB --eif-path $EIF_NAME --enclave-cid $ENCLAVE_CID"
