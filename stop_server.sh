#!/bin/bash
# Stop script for the distributed server system
# Stops uvicorn, Nitro Enclave, and vsock-proxy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR}"
STARTUP_LOG="$LOG_DIR/startup.log"

mkdir -p "$LOG_DIR"

log() {
  echo "[$(date)] $*" | tee -a "$STARTUP_LOG"
}

terminate_pattern() {
  local pattern="$1"
  local name="$2"

  if ! pgrep -f "$pattern" >/dev/null 2>&1; then
    log "$name is not running."
    return 0
  fi

  log "Stopping $name..."
  pkill -f "$pattern" 2>/dev/null || true

  sleep 2
  if pgrep -f "$pattern" >/dev/null 2>&1; then
    log "Force-stopping $name..."
    pkill -9 -f "$pattern" 2>/dev/null || true
  fi

  if pgrep -f "$pattern" >/dev/null 2>&1; then
    log "WARNING: Failed to stop $name completely."
  else
    log "$name stopped."
  fi
}

log "Stopping distributed server system..."

# 1) Stop uvicorn for this app
terminate_pattern "proxy_ec2:app" "uvicorn (proxy_ec2)"

# 2) Stop Nitro Enclave(s)
if command -v nitro-cli >/dev/null 2>&1; then
  log "Terminating Nitro Enclave(s)..."
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
  sleep 1

  ENCLAVE_DESCR="$(nitro-cli describe-enclaves 2>/dev/null || echo "[]")"
  if echo "$ENCLAVE_DESCR" | grep -q "\"EnclaveID\""; then
    log "WARNING: Some enclave instances may still be running."
  else
    log "Nitro Enclave(s) terminated."
  fi
else
  log "WARNING: nitro-cli not found; skipping enclave termination."
fi

# 3) Stop vsock-proxy
if pgrep vsock-proxy >/dev/null 2>&1; then
  log "Stopping vsock-proxy..."
  pkill vsock-proxy 2>/dev/null || true
  sleep 1
  if pgrep vsock-proxy >/dev/null 2>&1; then
    log "Force-stopping vsock-proxy..."
    pkill -9 vsock-proxy 2>/dev/null || true
  fi

  if pgrep vsock-proxy >/dev/null 2>&1; then
    log "WARNING: Failed to stop vsock-proxy completely."
  else
    log "vsock-proxy stopped."
  fi
else
  log "vsock-proxy is not running."
fi

log "Stop sequence complete."
