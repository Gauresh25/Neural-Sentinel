#!/bin/bash
# Shellcode — simulates large-payload delivery over established TCP connections.
#
# Expected detection: "Shellcode" label
#   → avg_smean > 600   (large source packets: 4 KB payload / ~6 pkts ≈ 700 B/pkt)
#   → avg_sbytes > 3000 (total source bytes per flow well above threshold)
#   → established >= 5  (each curl completes a full SYN→data→FIN handshake → state FIN)
#   → src_concentrated  (all flows from attacker IP)
#
# Each curl sends a 4 KB binary-like body over its own TCP connection
# (Connection: close). The sentinel's FastAPI returns 422/404 — that's fine,
# the IDS sees the raw flow features, not the HTTP status.
#
# Usage: ./run_shellcode.sh [target] [port]
TARGET=${1:-sentinel}
PORT=${2:-8000}
BASE="http://$TARGET:$PORT"

# 8192-byte payload — needs to be large enough that avg_smean > 600 even after
# ACK/SYN/FIN packets dilute the per-flow mean. 4 KB sits right at the boundary;
# 8 KB pushes smean to ~1000 B/pkt with certainty.
PAYLOAD=$(python3 -c "print('A' * 8192)")

echo "[*] Shellcode delivery simulation → $BASE"
echo "    Sending 12 x 4 KB payloads over separate TCP connections"

for i in $(seq 1 12); do
    curl -s -o /dev/null \
         -w "    flow $i → %{http_code} (%{size_upload} B sent)\n" \
         -X POST \
         -H "Connection: close" \
         -H "Content-Type: application/octet-stream" \
         -H "User-Agent: NullBot/1.0" \
         --data-binary "$PAYLOAD" \
         --connect-timeout 5 \
         "$BASE/sink" &
done
wait

echo "[*] Shellcode simulation complete."
