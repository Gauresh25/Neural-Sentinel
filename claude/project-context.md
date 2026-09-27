# Neural Sentinel — Project Context (for Claude Code)

This file is a companion to `goals.md` in this same folder. `goals.md` is the MLOps build plan
(CI/CD, monitoring, model registry, incremental retraining, federated learning). This file is
background on the underlying ML/security project itself, plus an honest note on where the repo
actually stands relative to that plan as of 2026-09-11.

---

## What Neural Sentinel is

A decentralized, deep-learning-based Network Intrusion Detection System (NIDS). Core idea:
Bidirectional LSTM (Bi-LSTM) for sequence-aware attack detection, plus blockchain-based
tamper-evident logging of alerts, based on the AGLSTM architecture from:

> Bajpai SA, Patankar AB. "Self-configuring intrusion detection using adaptive goal target
> optimization based deep Bi-LSTM in blockchain networking systems." Intelligent Decision
> Technologies. 2025;19(1):175-193.

Team: Group 4 — Yash Shelar, Gauresh Bagayatkar, Vedant Chaudhari, Ocean Chaudhary.

### Why Bi-LSTM (not a transformer)
- Sequential memory matters for IDS: attacks are multi-step (recon → scan → exploit →
  exfiltration), and each step is only suspicious in the context of prior steps.
- Bi-LSTM runs forward + backward passes and concatenates them, so both "this is building up"
  and "looking back, this was coordinated" signals are available.
- Deliberately chosen over transformers/GNNs for practical reasons: far cheaper to train/run
  (2-4GB RAM vs 16-32GB), works with the modest dataset sizes available (100K-250K samples,
  transformers need 10M+), predictable low-latency inference (10-50ms vs 50-500ms), and — most
  relevant to the interview story — produces naturally interpretable step-by-step sequential
  logs rather than an attention-map black box. The 0.04% accuracy gap to transformers is judged
  not worth 10x the compute cost.

### AGLSTM optimizer (the "self-configuring" part)
A hybrid bio-inspired optimizer combining the Cheetah algorithm (fast exploitation once a good
region of weight-space is found) and the Rider algorithm (broad, sustained exploration,
avoids getting stuck in local optima). Roughly: early iterations favor Rider-style exploration,
later iterations shift to Cheetah-style rapid refinement. This is a research-paper-level
contribution being reimplemented here — Phase 1 of this repo uses plain Adam; AGLSTM itself is
explicitly deferred ("phase 2" per CLAUDE.md, separate from the goals.md MLOps phases).

### Blockchain layer
Rationale: centralized IDS logs are a single point of failure and can be tampered with by an
attacker who gains access. Detections get hashed and written to a local blockchain
(`src/local_blockchain.py`) for a tamper-evident audit trail, with the framing (per the paper)
that this could extend to cross-organization consensus / threat-intel sharing — which is the
same motivation goals.md gives for eventually adding federated learning (Phase 2 of the MLOps
plan): "share model improvements without sharing raw traffic data."

### Datasets
| Dataset | Records | Attack categories | Year |
|---|---|---|---|
| NSL-KDD | ~150K | 4 (DoS, Probe, R2L, U2R) | 2015 |
| UNSW-NB15 | ~257K | 9 (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms) | 2017 |
| BoT-IoT | 72M (5% sample used, ~3.6M) | DDoS, DoS, Reconnaissance, Theft | 2019 |

Reported benchmark numbers (paper/technical summary; **known to be inflated by dataset
artifacts in the literature** — goals.md explicitly flags this as something to be upfront about,
not lead with):
- UNSW-NB15: 99.93% accuracy, 99.92% sensitivity, 99.94% specificity
- BoT-IoT: 99.70% accuracy, 99.52% sensitivity, 99.41% specificity

Feature subset alignment across all three datasets is NOT yet resolved — goals.md Week 8 for
Phase 2 (federated learning) flags this as an open question requiring a dedicated session, since
the datasets don't share identical schemas.

---

## Actual repo state vs. goals.md assumptions (checked 2026-09-11)

goals.md was written assuming a fairly bare repo (Week 1 Session 1 = "rewrite README from a
stub"). **That's out of date for the local checkout** — the local repo at
`C:\Other files\GitHub\neural-sentinel` is significantly further along than what's synced to
GitHub (`Gauresh25/Neural-Sentinel`, branch `main`), which still shows a 2-line README stub.
Locally:

- `README.md` (~15KB) is already fully written: architecture diagram, dataset tables, results,
  federated learning section, blockchain logging section, live demo environment, API reference,
  project structure, setup instructions. **Week 1 Session 1 of goals.md is effectively done
  locally — it just hasn't been pushed/synced.**
- `src/` is now split into `api/` (`inference_server.py` FastAPI app, `dashboard.html`),
  `streaming/` (`stream_processor.py` — scapy-based live packet capture → flow reconstruction,
  ~23KB, substantial), and `blockchain/` (`local_blockchain.py` — SHA-256 tamper-evident logging).
  Week 1 Session 2's reorg is done (2026-09-11), using `api/`/`streaming/`/`blockchain/` rather
  than goals.md's literal `api/`/`training/`/`preprocessing/`, since no training or preprocessing
  code actually lives in `src/` — that logic is still only in the notebooks (see below).
- `docker/` has four subfolders: `attacker` (with dos/fuzz/recon/ssh_brute attack scripts),
  `frontend`, `sentinel`, `victim` — each with a Dockerfile — plus a root `docker-compose.yml`.
  This is a live attack-simulation demo environment, well beyond what goals.md Week 1-2 assumes
  exists yet.
- `frontend/` is a full Vite/React/TypeScript dashboard app (not just `dashboard.html`).
- `models/` has two `.keras` model files, plus `baseline_lstm_model.pth` and
  `best_simple_lstm_model.pth` — moved in from repo root 2026-09-11 (was Week 1 Session 2 item 4).
  Note: `notebooks/02_simple_lstm.ipynb` still hardcodes `torch.save(model.state_dict(),
  'baseline_lstm_model.pth')` — a relative path — so re-running that notebook will drop a fresh
  stray copy wherever its cwd is, not into `models/`. Not fixed as part of this cleanup; worth
  a follow-up if it keeps happening. `best_simple_lstm_model.pth` isn't referenced by that name
  in any notebook — looks like an orphan from an earlier run/rename.
- `Report.docx` (~1.7MB) exists at repo root — likely the written project report/thesis.
- `condaenv.vy1ii5xz.requirements.txt` (stray auto-generated conda export) removed 2026-09-11.
- **Genuinely not started** (consistent with goals.md's "not done" list): no `tests/` directory
  anywhere, no `.github/workflows/` at all — so CI (Week 1 Sessions 3-7) and everything
  downstream of it (Week 2 image builds, Week 3 CD) is real, un-started work.
- `CLAUDE.md` at repo root is stale — it says "model training notebook NOT YET WRITTEN,"
  "stream processor NOT YET WRITTEN," "Docker demo NOT YET SET UP," none of which is true
  anymore given the above. Worth rewriting/updating alongside Week 1 work, since Claude Code
  reads it automatically as project instructions.

### Practical implication for where to actually start
Don't blindly follow goals.md's session-by-session order as if starting from zero. A more
accurate Week 1 for *this* repo:
1. Confirm local README is good enough as-is, or just polish/sync it to GitHub (Session 1 is
   ~done, just needs pushing + maybe a couple gaps filled, e.g. is there a results table sourced
   from real training runs or just the paper's numbers — worth checking which).
2. Update the stale `CLAUDE.md`.
3. ~~Do the `src/` reorg~~ — done 2026-09-11 (`api/`/`streaming/`/`blockchain/`, see above).
4. ~~Move stray `.pth` files into `models/`, remove the stray conda export~~ — done 2026-09-11.
5. Then Sessions 3 onward (pytest, FastAPI smoke test, ruff/black/pre-commit, CI workflow) are
   all genuinely un-started and should proceed as goals.md describes.

---

## Source documents (held in the Claude project, not yet copied into this repo)
- `Neural Sentinel_ Complete Technical Summary.pdf` — the source for most of the background
  above (LSTM/Bi-LSTM/AGLSTM explanations, comparison tables, blockchain rationale, full
  performance tables, implementation roadmap).
- `Project presentation.pdf` — the original slide deck; the architecture diagram in README.md
  was meant to be reused from this per goals.md.
- `bajpaipatankar2025selfconfiguringintrusiondetectionusingadaptivegoaltargetoptimizationbased.pdf`
  — the source academic paper for AGLSTM.

These weren't copied into this folder (they're PDFs living in the Claude project) — ask Claude
(in Cowork) to pull specific figures/numbers from them on demand, or ask the user to export them
into `docs/` if Claude Code needs to reference them directly and repeatedly.
