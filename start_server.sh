#!/bin/bash
# Startup script for the distributed server system
# Run on EC2 boot to start vsock-proxy, enclave, and uvicorn

set -e

APP_DIR="/home/ec2-user/distributed-server"
LOG_DIR="/home/ec2-user/logs"
mkdir -p "$LOG_DIR"

echo "[$(date)] Starting distributed server system..." | tee -a "$LOG_DIR/startup.log"

# 0. Flush Redis cache (stale kfrags/public keys cause decryption failures after restart)
echo "[$(date)] Flushing Redis cache..." | tee -a "$LOG_DIR/startup.log"
valkey-cli FLUSHALL >> "$LOG_DIR/startup.log" 2>&1 || echo "[$(date)] WARNING: valkey-cli FLUSHALL failed" | tee -a "$LOG_DIR/startup.log"

# 1. Start vsock-proxy (bridges enclave to KMS)
echo "[$(date)] Starting vsock-proxy..." | tee -a "$LOG_DIR/startup.log"
pkill vsock-proxy 2>/dev/null || true
sleep 1
vsock-proxy 8001 kms.eu-west-2.amazonaws.com 443 &
echo "[$(date)] vsock-proxy started (PID: $!)" | tee -a "$LOG_DIR/startup.log"

# 2. Terminate any old enclaves
nitro-cli terminate-enclave --all 2>/dev/null || true

# 3. Start the enclave
echo "[$(date)] Starting Nitro Enclave..." | tee -a "$LOG_DIR/startup.log"
cd "$APP_DIR"
nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 2048 \
  --eif-path proxy-enclave.eif \
  --enclave-cid 16 \
  >> "$LOG_DIR/enclave.log" 2>&1

# Wait for enclave to boot
sleep 5

# Verify enclave is running
ENCLAVE_STATUS=$(nitro-cli describe-enclaves | python3 -c "import sys,json; encs=json.load(sys.stdin); print(encs[0]['State'] if encs else 'NOT_RUNNING')" 2>/dev/null)
echo "[$(date)] Enclave status: $ENCLAVE_STATUS" | tee -a "$LOG_DIR/startup.log"

if [ "$ENCLAVE_STATUS" != "RUNNING" ]; then
  echo "[$(date)] ERROR: Enclave failed to start!" | tee -a "$LOG_DIR/startup.log"
  exit 1
fi

# 4. Start uvicorn
echo "[$(date)] Starting uvicorn..." | tee -a "$LOG_DIR/startup.log"
cd "$APP_DIR"
python3.11 -m uvicorn proxy_ec2:app --host 0.0.0.0 --port 8000 \
  >> "$LOG_DIR/uvicorn.log" 2>&1 &
echo "[$(date)] uvicorn started (PID: $!)" | tee -a "$LOG_DIR/startup.log"

echo "[$(date)] All services started successfully." | tee -a "$LOG_DIR/startup.log"
