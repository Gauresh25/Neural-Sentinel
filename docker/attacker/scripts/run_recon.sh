#!/bin/bash
# Reconnaissance — SYN port scan against sentinel
# Simulates the "Reconnaissance" category from UNSW-NB15
TARGET=${1:-sentinel}
echo "[*] Starting port scan against $TARGET ..."
nmap -sS -p 1-1000 --min-rate 200 -T4 "$TARGET"
echo "[*] Recon complete."
