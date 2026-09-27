#!/bin/bash
set -e

# Start SSH daemon in background (demo target for brute-force attacks)
/usr/sbin/sshd -e
echo "[Sentinel] sshd started on port 2222 (auth logs → stdout)"

# Start the IDS inference server (foreground)
exec python -m uvicorn api.inference_server:app --host 0.0.0.0 --port 8000
