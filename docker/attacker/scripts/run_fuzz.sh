#!/bin/bash
# Fuzzer — HTTP path + method fuzzing against sentinel:8000
#
# The 404 responses you see are EXPECTED and correct.
# A fuzzer probes paths that don't exist — the 404s ARE the attack traffic.
# Detection relies on http_methods counts per flow, not HTTP status codes.
#
# Key flag: -H "Connection: close" forces a new TCP connection per request.
# Without it, HTTP/1.1 keep-alive bundles all requests into 1-2 flows,
# making the window look like normal traffic instead of a fuzzer sweep.
#
# Expected detection: "Fuzzers" label, confidence 0.70+
#   → http_hits ≥ 8  (each flow carries one HTTP method verb in payload)
#   → http_flows ≥ 6 (service="http" since port 8000 is mapped)
#   → src_concentrated (all from attacker)
#
# Usage: ./run_fuzz.sh [target] [port]
TARGET=${1:-sentinel}
PORT=${2:-8000}
BASE="http://$TARGET:$PORT"

echo "[*] HTTP fuzzer → $BASE"
echo "    404 responses are expected — they confirm the fuzzer is probing correctly."

# Phase 1 — method enumeration: 8 different HTTP verbs, one TCP connection each
echo "    [phase 1] method probe (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/TRACE)"
for method in GET POST PUT DELETE HEAD OPTIONS PATCH TRACE; do
    curl -s -o /dev/null \
         -w "    $method → %{http_code}\n" \
         -X "$method" \
         -H "Connection: close" \
         -H "User-Agent: FuzzBot/1.0" \
         --connect-timeout 2 \
         "$BASE/" &
done
wait

# Phase 2 — GET path brute-force: each path = new TCP connection (Connection: close)
echo "    [phase 2] GET path brute-force ($(wc -l < /wordlist.txt | tr -d ' ') paths)"
wfuzz -c \
      -z file,/wordlist.txt \
      -t 20 \
      --hc 000 \
      -H "Connection: close" \
      -H "User-Agent: FuzzBot/1.0" \
      "$BASE/FUZZ" 2>&1 || true

# Phase 3 — POST sweep: same paths with POST body (raises http_hits faster)
echo "    [phase 3] POST sweep"
wfuzz -c \
      -z file,/wordlist.txt \
      -t 15 \
      -X POST \
      --hc 000 \
      -H "Connection: close" \
      -H "User-Agent: FuzzBot/1.0" \
      -d "x=FUZZ" \
      "$BASE/FUZZ" 2>&1 || true

echo "[*] Fuzzing complete."
