#!/bin/bash
# Reconnaissance — SYN port scan against SENTINEL (not victim).
#
# Why sentinel and not victim:
#   The IDS sniffs its own network interface (eth0 on ids-net). It can see all
#   traffic directed at itself, but Docker bridge does not forward traffic
#   between OTHER containers to the sentinel's veth. Scanning sentinel directly
#   guarantees every probe packet is visible to the IDS.
#
# Expected detection: "Reconnaissance" label, confidence 0.75+
#   → src_concentrated (all flows from attacker IP)
#   → unique_dst_ports ≥ 6 (hundreds of different ports scanned)
#   → unanswered ≥ 5 (most ports closed, reply RST = no handshake)
#   → avg_total_pkts ≤ 5 (1-2 pkts per probe flow)
#
# Usage: ./run_recon.sh [target] [port_range]
TARGET=${1:-sentinel}
PORTS=${2:-1-9000}

echo "[*] SYN port scan → $TARGET ports $PORTS"
echo "    Each probe = 1 SYN pkt → RST reply (closed) or SYN-ACK (open)"
echo "    At 200 probes/sec the flow window fills with recon-pattern flows fast"

# -sS          : stealth SYN scan (half-open, RST to kill handshake on open ports)
# --max-rate 200: fast enough to dominate the 10-flow window vs background traffic
# -T4          : aggressive timing, minimal retransmit wait — keeps scan short
# -n           : skip reverse DNS (reduces noise in flow tracker)
# -p 1-9000    : wide port range → guarantees >>6 unique dst_ports per window
nmap -sS -p "$PORTS" --max-rate 200 -T4 -n "$TARGET"

echo "[*] Recon complete."
