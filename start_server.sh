#!/bin/bash
# Startup script for the distributed server system
# Run on EC2 boot to start vsock-proxy, enclave, and uvicorn

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$SCRIPT_DIR}"
LOG_DIR="${LOG_DIR:-$HOME/logs}"

mkdir -p "$LOG_DIR"
STARTUP_LOG="$LOG_DIR/startup.log"
ENCLAVE_LOG="$LOG_DIR/enclave.log"
UVICORN_LOG="$LOG_DIR/uvicorn.log"

log() {
  echo "[$(date)] $*" | tee -a "$STARTUP_LOG"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR: Required command not found: $cmd"
    exit 1
  fi
}

check_process_alive() {
  local pid="$1"
  local name="$2"
  if ! kill -0 "$pid" 2>/dev/null; then
    log "ERROR: $name failed to stay running (PID $pid)."
    return 1
  fi
  return 0
}

check_tcp_port_open() {
  local host="$1"
  local port="$2"
  local retries="$3"
  local delay="$4"
  local i
  for ((i = 1; i <= retries; i++)); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- 3<&-
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

log "Starting distributed server system..."
log "APP_DIR=$APP_DIR"
log "LOG_DIR=$LOG_DIR"

require_cmd valkey-cli
require_cmd vsock-proxy
require_cmd nitro-cli
require_cmd python3.11

if [ ! -d "$APP_DIR" ]; then
  log "ERROR: APP_DIR does not exist: $APP_DIR"
  exit 1
fi

if [ ! -f "$APP_DIR/proxy-enclave.eif" ]; then
  log "ERROR: Missing EIF at $APP_DIR/proxy-enclave.eif"
  exit 1
fi

if [ ! -f "$APP_DIR/proxy_ec2.py" ]; then
  log "ERROR: Missing proxy_ec2.py at $APP_DIR"
  exit 1
fi

# Load runtime env so region and app settings stay in sync with proxy_ec2.py / proxy_enclave.py
if [ -f "$APP_DIR/.env.local" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$APP_DIR/.env.local"
  set +a
  log "Loaded environment from $APP_DIR/.env.local"
else
  log "WARNING: .env.local not found in $APP_DIR; using process environment/defaults"
fi

AWS_REGION="${AWS_REGION:-eu-west-2}"
KMS_ENDPOINT="kms.${AWS_REGION}.amazonaws.com"
log "Using AWS_REGION=$AWS_REGION and KMS endpoint $KMS_ENDPOINT"

# 0. Flush Redis cache (stale kfrags/public keys cause decryption failures after restart)
log "Flushing Redis cache..."
valkey-cli FLUSHALL >>"$STARTUP_LOG" 2>&1 || log "WARNING: valkey-cli FLUSHALL failed"

# 1. Start vsock-proxy (bridges enclave to KMS)
log "Starting vsock-proxy..."
pkill vsock-proxy 2>/dev/null || true
sleep 1
vsock-proxy 8001 "$KMS_ENDPOINT" 443 >>"$STARTUP_LOG" 2>&1 &
VSOCK_PROXY_PID=$!
sleep 1
check_process_alive "$VSOCK_PROXY_PID" "vsock-proxy"
log "vsock-proxy started (PID: $VSOCK_PROXY_PID)"

# 2. Terminate any old enclaves
nitro-cli terminate-enclave --all 2>/dev/null || true

# 3. Start the enclave
log "Starting Nitro Enclave..."
cd "$APP_DIR"
nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 2048 \
  --eif-path proxy-enclave.eif \
  --enclave-cid 16 \
  >>"$ENCLAVE_LOG" 2>&1

# Wait for enclave to boot
sleep 5

# Verify enclave is running
ENCLAVE_STATUS=$(
  nitro-cli describe-enclaves | \
    python3 -c "import sys,json; encs=json.load(sys.stdin); print(encs[0]['State'] if encs else 'NOT_RUNNING')" 2>/dev/null
)
log "Enclave status: $ENCLAVE_STATUS"

if [ "$ENCLAVE_STATUS" != "RUNNING" ]; then
  log "ERROR: Enclave failed to start."
  exit 1
fi

# 4. Start uvicorn
log "Starting uvicorn..."
cd "$APP_DIR"
python3.11 -m uvicorn proxy_ec2:app --host 0.0.0.0 --port 8000 \
  >>"$UVICORN_LOG" 2>&1 &
UVICORN_PID=$!

sleep 2
check_process_alive "$UVICORN_PID" "uvicorn"

if check_tcp_port_open "127.0.0.1" "8000" 10 1; then
  log "uvicorn started (PID: $UVICORN_PID) and port 8000 is accepting connections"
else
  log "ERROR: uvicorn process is running but port 8000 did not open in time"
  exit 1
fi

log "All services started successfully."
