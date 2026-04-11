#!/bin/bash
# Fuzzer — HTTP directory brute-force against sentinel
# Simulates the "Fuzzers" category from UNSW-NB15
TARGET=${1:-sentinel}
PORT=${2:-8000}
echo "[*] Starting HTTP fuzzer against http://$TARGET:$PORT ..."
wfuzz -c -z file,/wordlist.txt \
      --hc 404 \
      -t 20 \
      "http://$TARGET:$PORT/FUZZ" 2>&1 || true
echo "[*] Fuzzing complete."
