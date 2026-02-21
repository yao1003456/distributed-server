#!/bin/bash
set -e

echo "=== Enclave Boot ==="
echo "Date: $(date)"
echo "Python: $(python --version 2>&1)"
echo "Checking AF_VSOCK..."
python -c "import socket; print('AF_VSOCK available:', hasattr(socket, 'AF_VSOCK'))"
echo "=== Starting Application ==="

# Run the app; if it crashes, keep enclave alive so console can be read
python /app/proxy_enclave.py 2>&1 || {
    EXIT_CODE=$?
    echo ""
    echo "=== APPLICATION CRASHED ==="
    echo "Exit code: $EXIT_CODE"
    echo "Keeping enclave alive for 1 hour for debugging..."
    sleep 3600
}
