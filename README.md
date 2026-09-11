# Neural Sentinel

A real-time Network Intrusion Detection System (NIDS) powered by a Bidirectional LSTM neural network, with live packet capture, a React dashboard, tamper-evident blockchain alert logging, and a full Docker demo environment with simulated attacks.

Based on the AGLSTM architecture from *Bajpai & Patankar (2025)* — currently implements Phase 1 (Bi-LSTM baseline + federated learning simulation). Phase 2 (attention layer + goal-adaptive optimizer) is planned.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Datasets](#datasets)
- [Model](#model)
- [Results](#results)
- [Federated Learning](#federated-learning)
- [Local Blockchain Logging](#local-blockchain-logging)
- [Live Demo Environment](#live-demo-environment)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Setup](#setup)

---

## Architecture Overview

```
Live Network Traffic
       │
       ▼
┌──────────────────┐
│  Stream Processor │  scapy packet capture → flow reconstruction → UNSW-NB15 features
└────────┬─────────┘
         │  10-flow sequences  (batch, 10, 44)
         ▼
┌──────────────────┐
│   Bi-LSTM Model  │  Bidirectional(LSTM(128)) → Dropout(0.3) → Dense(64) → Dense(1)
└────────┬─────────┘
         │  attack probability ∈ [0, 1]
         ▼
┌──────────────────────────────────────┐
│  score ≥ threshold?                  │
│  YES → heuristic_attack_type()       │  classifies into 9 UNSW-NB15 categories
│      → Local Blockchain add_block()  │  SHA-256 tamper-evident alert record
│      → SSE push to dashboard         │
└──────────────────────────────────────┘
```

The inference server runs as a FastAPI app. The stream processor runs in a background thread, pushing completed 10-flow windows to the model. Alerts stream to the React dashboard over Server-Sent Events.

---

## Datasets

Two benchmark IDS datasets are used, both preprocessed and saved as `.npy` sequences.

### NSL-KDD

| Split | Sequences | Features | Shape |
|---|---|---|---|
| Train | 134,677 | 40 | (134677, 10, 40) |
| Test | 22,535 | 40 | (22535, 10, 40) |

- Attack rate in train: **50.0%** (SMOTE-balanced)
- Attack rate in test: **56.9%** (natural)
- Removed: `num_outbound_cmds` (constant column, zero variance)
- Categorical features (`protocol_type`, `service`, `flag`) label-encoded

40 features cover: connection duration, protocol, service, flag state, byte counts, error rates, host-based traffic statistics, and 9 derived rate features.

**Attack categories:** DoS, Probe, R2L, U2R

### UNSW-NB15

| Split | Sequences | Features | Shape |
|---|---|---|---|
| Train | 238,673 | 44 | (238673, 10, 44) |
| Test | 82,323 | 44 | (82323, 10, 44) |

- Attack rate in train: **50.0%** (SMOTE-balanced)
- Attack rate in test: **55.1%** (natural)
- 44 features cover flow-level statistics: packet counts, byte counts, inter-packet timing, jitter, TCP flags, window sizes, RTT components, sliding-window connection counts (`ct_*`), and application-layer indicators (`is_ftp_login`, `ct_flw_http_mthd`)

**Attack categories:** DoS, Exploits, Reconnaissance, Fuzzers, Backdoor, Shellcode, Worms, Analysis, Brute Force

---

## Model

**Architecture: Bidirectional LSTM**

```
Input       (batch, 10, n_features)
    ↓
Bidirectional(LSTM(128))    → output: (batch, 256)   [128 forward + 128 backward]
    ↓
Dropout(0.3)
    ↓
Dense(64, activation='relu')
    ↓
Dense(1, activation='sigmoid')   → attack probability
```

| Parameter | Value |
|---|---|
| Optimizer | Adam |
| Loss | Binary cross-entropy |
| Batch size | 128 |
| Max epochs | 20 |
| Early stopping | patience=3, monitor=val_loss |
| LR reduction | factor=0.5, patience=2, min=1e-5 |
| Classification threshold | 0.5 |

**NSL-KDD model parameters:** 189,569 (740 KB)
**UNSW-NB15 model parameters:** 193,665 (756 KB)

The production inference server loads `bilstm_unsw_nb15.keras` as it matches the live feature extraction pipeline in the stream processor.

---

## Results

### NSL-KDD Test Set (22,535 sequences)

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Normal | 0.67 | 0.98 | 0.79 | 9,707 |
| Attack | 0.97 | 0.63 | 0.77 | 12,828 |
| **Weighted avg** | **0.84** | **0.78** | **0.78** | **22,535** |

| Metric | Value |
|---|---|
| Accuracy | **77.95%** |
| Precision | **97.25%** |
| Recall | **63.05%** |
| F1-Score | **76.50%** |

The high precision (97%) means nearly every flagged sequence is a true attack. The lower recall (63%) reflects the model's conservative threshold — it misses ~37% of attacks rather than generating false positives. This is the intended trade-off for a production IDS where alert fatigue is costly.

### UNSW-NB15 Test Set (82,323 sequences)

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Normal | 0.76 | 1.00 | 0.87 | 36,991 |
| Attack | 1.00 | 0.75 | 0.85 | 45,332 |
| **Weighted avg** | **0.89** | **0.86** | **0.86** | **82,323** |

| Metric | Value |
|---|---|
| Accuracy | **86.01%** |
| Precision | **100.00%** |
| Recall | **74.60%** |
| F1-Score | **85.45%** |

Perfect precision (1.00) on UNSW-NB15 — zero false positives in the test set. The model is highly conservative but reliable: every alert it raises is a real attack. The UNSW model is used in production because its feature set maps directly to live flow extraction.

---

## Federated Learning

`notebooks/04_federated_learning.ipynb` implements a simulated federated learning protocol on NSL-KDD.

### Protocol

```
M0 (pre-trained Bi-LSTM)
    │
    ├── Clone → Node 0  (44,892 samples)
    ├── Clone → Node 1  (44,892 samples)
    └── Clone → Node 2  (44,893 samples)

For each FL round (5 total):
    Each node: fit locally for 2 epochs (batch=128)
    Collect weights from all 3 nodes
    FedAvg: weighted mean proportional to dataset size
    Broadcast global weights back to all nodes

Evaluate global model on held-out test set
```

**FedAvg formula:**

```
W_global = Σ (n_i / N) × W_i
```

where `n_i` is node i's dataset size and `N` is total samples across all nodes.

### Limitations

The simulation correctly implements the FL mechanics (local training, weight serialisation, weighted aggregation, broadcast). However, all nodes are partitioned from the same centralised dataset on the same machine. The privacy guarantee is a simulation artefact. FL produces measurable benefit only when nodes have genuinely different data distributions — e.g. different organisations sharing model updates without exposing internal traffic logs. This notebook demonstrates the *protocol*, not the *real-world benefit*.

---

## Local Blockchain Logging

Every attack detection is appended to a SHA-256 linked block chain persisted at `logs/blockchain.json`.

### Block Structure

```json
{
  "index": 42,
  "timestamp": 1713187200.123,
  "prev_hash": "a3f9d2...",
  "data": {
    "event": "alert",
    "attack_type": "Reconnaissance",
    "confidence": 0.9341,
    "src_ip": "172.20.0.4",
    "dst_ip": "172.20.0.2",
    "proto": "tcp",
    "service": "-",
    "time": "14:32:07"
  },
  "hash": "7c4e1b..."
}
```

- Genesis block (index 0) created automatically on first startup with `prev_hash = "0" * 64`
- `hash = SHA256(index + timestamp + prev_hash + data)` — computed over canonical JSON
- Only attack events are logged; normal traffic is not recorded
- Writes are atomic: JSON written to `.tmp` then renamed, preventing corruption on crash
- Chain survives container restarts — existing history is preserved

### Tamper Evidence

Editing any field in any historical block breaks every hash from that point forward:

```json
GET /chain/verify
→ { "valid": false, "length": 47, "broken_at": 3, "reason": "hash mismatch" }
```

A clean chain:

```json
→ { "valid": true, "length": 47, "broken_at": null }
```

---

## Live Demo Environment

Four Docker containers on a shared bridge network (`ids-net`):

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  sentinel   │    │   victim    │    │  attacker   │    │  frontend   │
│  :8000 API  │    │  SSH :22    │    │  (manual)   │    │  :3000      │
│  :2222 SSH  │    │             │    │             │    │  nginx      │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       └──────────────────┴──────────────────┴──────────────────┘
                              ids-net (bridge)
```

### Quick Start

```bash
docker-compose up --build
```

- Dashboard: http://localhost:3000
- API docs: http://localhost:8000/docs
- Blockchain viewer: http://localhost:8000/chain

### Attack Simulations

Exec into the attacker container:

```bash
docker exec -it attacker bash
```

| Script | Attack Type | Tool | Detection Category |
|---|---|---|---|
| `./run_dos.sh` | SYN flood | hping3 --flood | **DoS** |
| `./run_recon.sh` | SYN port scan | nmap -sS | **Reconnaissance** |
| `./run_ssh_brute.sh` | Credential stuffing | Hydra | **Brute Force (SSH)** |
| `./run_fuzz.sh` | HTTP path fuzzing | wfuzz + curl | **Fuzzers** |
| `./run_shellcode.sh` | Large-payload delivery | curl | **Shellcode** |

All scripts accept optional arguments: `./run_dos.sh [target] [duration_seconds]`

### Detection Heuristics

When the model scores a sequence above threshold, `heuristic_attack_type()` classifies it using flow-level signatures:

| Category | Key Signal |
|---|---|
| Brute Force (SSH) | ≥5 flows to port 22/2222 |
| Backdoor | ≥5 FTP flows from same source, or long bidirectional tunnel (avg_dur >30s) |
| Reconnaissance | Single source, ≥6 unique dst ports, mostly unanswered, ≤5 pkts/flow |
| Fuzzers | ≥6 HTTP flows + ≥5 HTTP method hits from same source |
| DoS | Response <10% of sent packets, or port-concentrated SYN flood |
| Worms | Same source reaching ≥7 distinct destination IPs |
| Shellcode | avg packet >600B, established connections, >3KB total per flow |
| Exploits | ≥5 established connections to known service ports with non-trivial payload |
| Analysis | Moderate rate, bidirectional, does not fit above categories |

The heuristic can override the model: if a clear attack signature is present even when the model scores below threshold, the alert is still raised.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/dashboard` | Built-in single-file monitoring dashboard |
| GET | `/alerts` | Server-Sent Events stream of live detections |
| POST | `/predict` | Manual inference: `{"sequence": [[...], ...]}` (10×44) |
| GET | `/recent` | Last 500 alerts, newest first |
| GET | `/stats` | Totals, attack rate per minute, per-category counts |
| GET | `/summary` | Attack category breakdown |
| GET | `/confidence-distribution` | Prediction score histogram (10 bins) |
| GET | `/threat/{ip}` | All alerts involving a specific IP address |
| GET | `/threshold` | Current classification threshold |
| POST | `/threshold` | Update threshold: `{"threshold": 0.6}` |
| GET | `/chain` | Last N blockchain blocks + integrity status (`?limit=20`) |
| GET | `/chain/verify` | Chain integrity check only |
| POST | `/sink` | Data sink for shellcode simulation (discards body gracefully) |

---

## Project Structure

```
neural-sentinel/
│
├── notebooks/
│   ├── 01_data_preprocessing.ipynb     # NSL-KDD + UNSW-NB15: cleaning, encoding, SMOTE, sequences
│   ├── 02_simple_lstm.ipynb            # Unidirectional LSTM baseline
│   ├── 03_bilstm_training.ipynb        # Bi-LSTM training on both datasets → production models
│   └── 04_federated_learning.ipynb     # FL simulation: 3 nodes, 5 rounds, FedAvg, NSL-KDD
│
├── src/
│   ├── inference_server.py             # FastAPI: model loading, prediction, SSE, all endpoints
│   ├── stream_processor.py             # Packet capture, flow tracking, UNSW-NB15 feature extraction
│   ├── local_blockchain.py             # SHA-256 linked chain, thread-safe, atomic JSON persistence
│   └── dashboard.html                  # Fallback single-file dashboard
│
├── frontend/                           # React + TypeScript + Tailwind dashboard
│   └── src/
│       ├── components/
│       │   ├── AlertFeed.tsx           # Live SSE alert table
│       │   ├── AttackCategoryChart.tsx
│       │   ├── ConfidenceHistogram.tsx
│       │   ├── ThreatLookup.tsx        # Per-IP threat profile
│       │   └── ThresholdSlider.tsx
│       ├── hooks/useSSE.ts
│       └── api.ts
│
├── docker/
│   ├── sentinel/                       # Inference container (FastAPI + model + scapy)
│   ├── victim/                         # Weak SSH target for brute-force demo
│   ├── attacker/
│   │   └── scripts/                    # run_dos.sh, run_recon.sh, run_ssh_brute.sh, run_fuzz.sh, run_shellcode.sh
│   └── frontend/                       # nginx serving built React app
│
├── data/
│   ├── raw/                            # KDDTrain+.txt, KDDTest+.txt, UNSW CSVs
│   └── processed/
│       ├── nsl-kdd/                    # X_train.npy, y_train.npy, X_test.npy, y_test.npy, scaler.pkl, encoders.pkl
│       └── unsw-nb15/                  # same structure, 44 features
│
├── models/
│   ├── bilstm_nsl_kdd.keras            # NSL-KDD model (40 features, 189K params)
│   ├── bilstm_unsw_nb15.keras          # UNSW-NB15 model (44 features, 193K params) — production
│   └── bilstm_nsl_kdd_federated.keras  # Global model after 5 FL rounds
│
├── logs/
│   └── blockchain.json                 # Persistent alert chain (auto-created on first run)
│
├── docker-compose.yml
├── environment.yml                     # conda environment (Python 3.10)
└── requirements.txt
```

---

## Setup

### Option A — Docker (recommended for demo)

```bash
docker-compose up --build
# Dashboard:   http://localhost:3000
# API:         http://localhost:8000
# Blockchain:  http://localhost:8000/chain
```

### Option B — Local development

```bash
conda env create -f environment.yml
conda activate neural-sentinel

# Run notebooks in order to generate processed data and models
jupyter notebook

# Start inference server
cd src
uvicorn inference_server:app --host 0.0.0.0 --port 8000
```

> The stream processor requires raw socket access (scapy). On Linux: `sudo python inference_server.py`. On Windows: run terminal as Administrator. If scapy is unavailable the server starts normally — use `POST /predict` for manual testing.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `KERAS_BACKEND` | `torch` | Keras backend (`torch` or `tensorflow`) |
| `SNIFF_IFACE` | `eth0` | Network interface for packet capture |
| `KMP_DUPLICATE_LIB_OK` | `TRUE` | Suppress PyTorch/OpenMP warning on macOS/Windows |
