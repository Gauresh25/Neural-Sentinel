# Neural Sentinel — MLOps Build Plan

**Pace assumed:** ~2 hrs/day, ~10 weeks, ~140 hours total.
**Phase 1 (single-model MLOps + incremental learning):** Weeks 1–7 (~98 hrs)
**Phase 2 (federated learning layer):** Weeks 8–10 (~42 hrs)

Check off each session as you go (`[ ]` → `[x]`) and jot the actual date next to it — future-you (and an interviewer, if you show this doc) will want to see this wasn't done in one weekend.

---

## Stack

| Concern | Tool | Why |
|---|---|---|
| CI | GitHub Actions | Free, standard, what most job postings actually name |
| Container registry | GHCR (ghcr.io) | Free, zero setup beyond a GitHub token |
| Cloud host | AWS EC2 Free Tier (t2.micro/t3.micro, Ubuntu 22.04) | Most recognized free-tier option on a resume; 1GB RAM, so we manage it deliberately (swap file, lean services) |
| CD | GitHub Actions → SSH deploy (`appleboy/ssh-action`) | Simple, no extra infra, gets you a real push-to-deploy pipeline |
| IaC (stretch) | Terraform, for the EC2 instance + security group only | Optional — do it only if you're ahead of schedule; even a tiny Terraform file is a real resume line |
| Experiment tracking + model registry + data versioning | DagsHub (hosted MLflow + DVC remote, free tier) | Self-hosting MLflow on a 1GB box is a fight not worth having; DagsHub gives you MLflow + DVC storage with zero infra to babysit |
| Monitoring (metrics) | `prometheus_client` in FastAPI + self-hosted Prometheus container on EC2 | Prometheus alone is lightweight enough for 1GB RAM |
| Dashboards | Grafana Cloud free tier, via `remote_write` from your Prometheus | Keeps Grafana off your tiny box entirely |
| Testing | pytest + FastAPI `TestClient` | Minimum viable, catches real regressions |
| Lint/format | ruff + black + pre-commit | Fast to add, makes CI look legitimate |
| Federated learning | Flower (`flwr`), PyTorch backend | The standard FL framework, well documented, plays nicely with your existing torch/keras stack |
| Federated topology | Docker Compose, multiple containers, one host | Per your call — simplest to build/debug; see the RAM note in Phase 2 about where this actually runs |

---

## Phase 1 — MLOps for the single model

### Week 1 — Repo hygiene, tests, first CI job
- [ ] Session 1: Rewrite `README.md` — architecture diagram (reuse your presentation's flowchart), setup instructions, results table. This alone visibly upgrades the repo.
- [ ] Session 2: Reorganize `src/` if needed into clear boundaries (`api/`, `training/`, `preprocessing/`) — don't over-engineer, just make it navigable.
- [ ] Session 3: Add `pytest`. Write unit tests for your preprocessing functions (`clean_data`, `create_sequences`, the SMOTE wrapper) using small synthetic inputs, not the real dataset.
- [ ] Session 4: Add a smoke test for the FastAPI app using `TestClient` — hits the inference endpoint with a dummy sequence, asserts a 200 and a valid response shape.
- [ ] Session 5: Add `ruff`, `black`, and a `pre-commit` config. Run once, fix what it flags.
- [ ] Session 6: Write `.github/workflows/ci.yml` — job runs on push/PR: install deps, lint, run pytest.
- [ ] Session 7: Get CI green. Fix whatever breaks (something will).

**Checkpoint:** every push runs lint + tests automatically. This is the DevOps floor everything else stands on.

### Week 2 — CI builds and publishes the image
- [ ] Session 1–2: Add a `docker build` job to the workflow (gate it on tests passing).
- [ ] Session 3: Push the image to GHCR on merge to `main`, tagged with both the git SHA and `latest`.
- [ ] Session 4: Add a Trivy (or similar) image scan step — cheap to add, real security-conscious signal.
- [ ] Session 5–6: Pull the image locally, `docker run` it, curl the endpoint — confirm the CI-built image actually works, not just "builds."
- [ ] Session 7: Buffer/catch-up.

**Checkpoint:** a merged PR produces a working, scanned, versioned image in your registry with no manual step.

### Week 3 — Cloud deployment (real CD)
- [ ] Session 1: Provision an AWS Free Tier EC2 instance (t2.micro or t3.micro, Ubuntu 22.04). Allocate an Elastic IP so the address doesn't change on you.
- [ ] Session 2: Security group — open 22 (SSH, restrict to your IP if possible), 8000 (API), 9090 (Prometheus, later).
- [ ] Session 3: SSH in, install Docker + docker-compose. **Add a 2GB swap file now** — torch + keras loading on 1GB RAM will otherwise OOM-kill you at the worst moment.
- [ ] Session 4: Manual first deploy — `docker compose pull && docker compose up -d`. Confirm the public IP serves the API.
- [ ] Session 5–6: Add the CD step to GitHub Actions — SSH into the box (via `appleboy/ssh-action`) and re-run the pull/up after a successful image push.
- [ ] Session 7: Push a trivial code change end to end, watch it auto-deploy, curl the public endpoint to confirm.

**Checkpoint:** code merged to `main` → live on a public URL within minutes, no manual step. This is the single most interview-legible milestone in the whole plan — get a screen recording of this once it works.

*(Optional, only if ahead: write a small Terraform config for the EC2 instance + security group, replacing the manual provisioning in Session 1–2.)*

### Week 4 — Experiment tracking + model registry
- [ ] Session 1: Create a DagsHub repo linked to your GitHub repo. Grab the MLflow tracking URI and DVC remote credentials.
- [ ] Session 2–3: Instrument your training script (pull the logic out of the notebook into a runnable `.py` if it isn't already) to log params, metrics, and the model artifact to MLflow on each run.
- [ ] Session 4: Run 2–3 training variations (different hyperparams or epoch counts), compare runs in the MLflow UI.
- [ ] Session 5: Register the best run's model in the MLflow Model Registry, transition it to `Production`.
- [ ] Session 6–7: Update the inference server to load the model from the registry at container start (pull by stage, e.g. `models:/neural-sentinel/Production`) instead of the model file being `COPY`'d into the image. This is the real architectural shift — the image becomes model-agnostic, and "which model is live" becomes a registry query, not a rebuild.

**Checkpoint:** you can promote a different model version in the registry, restart the container, and it serves the new model — no image rebuild.

### Week 5 — Monitoring
- [ ] Session 1–2: Add `prometheus_client` to the FastAPI app — request count, latency histogram, and a prediction-confidence histogram at minimum.
- [ ] Session 3: Add a simple drift signal — e.g. a rolling Population Stability Index (PSI) of recent input feature distributions vs. a saved reference distribution from training data, exposed as a Prometheus gauge. Doesn't need to be fancy; it needs to exist and move.
- [ ] Session 4: Deploy a Prometheus container on the EC2 box, scraping `/metrics`.
- [ ] Session 5: Set up a free Grafana Cloud account, configure `remote_write` from your Prometheus instance.
- [ ] Session 6: Build one dashboard — latency, throughput, confidence distribution, drift score.
- [ ] Session 7: Run your existing `attacker` container against the live deployment, watch the dashboard react in real time.

**Checkpoint:** a live dashboard that visibly moves when you throw traffic at the system. This is your best demo moment in an interview or viva — it makes "monitoring" tangible instead of a bullet point.

### Week 6 — Data buffer + incremental retraining
- [ ] Session 1: Build a "live traffic buffer" — a simple table (SQLite is fine, or a DVC-tracked parquet file) that accumulates newly seen samples.
- [ ] Session 2: Write a labeling-simulation script. **Be explicit about the simplification**: it uses true labels from a held-out slice of your existing datasets as a stand-in for a real labeling pipeline (real production labeling — SOC analyst review, delayed ground truth — is a genuinely hard separate problem; don't pretend otherwise if asked).
- [ ] Session 3–4: Write the incremental fine-tune script — load the current `Production` model from the registry, fine-tune a few epochs on the buffer, evaluate against a fixed holdout set, log the run to MLflow.
- [ ] Session 5: Add a promotion gate — only auto-promote the new model to `Production` if its holdout metrics are within tolerance of (or better than) the current production model; otherwise leave it flagged in the registry for manual review. This "guarded auto-promotion" idea is a real, interview-worthy MLOps concept — say it by name if asked.
- [ ] Session 6: Add a GitHub Actions workflow that runs the fine-tune script — triggerable manually (`workflow_dispatch`) and on a weekly cron.
- [ ] Session 7: Simulate a buffer of new data, trigger the workflow, confirm a new model version appears in the registry and gets promoted or correctly rejected.

**Checkpoint:** you can point to a concrete, working answer to "how does the model stay current" — not just a slide claim.

### Week 7 — Phase 1 polish & buffer week
- [ ] Session 1–3: Fix whatever's still broken from weeks 1–6 (budget for this honestly — something always needs it).
- [ ] Session 4: Finalize the architecture diagram and write the Phase 1 section of the README.
- [ ] Session 5–6: Record a demo: push code → CI → image built/scanned/pushed → auto-deployed → Grafana dashboard reacting to live traffic → manually trigger the retrain workflow → new model version promoted in the registry.
- [ ] Session 7: Watch the recording back, note anything embarrassing, fix it if quick.

**Phase 1 exit criteria:** end-to-end pipeline works unattended from a `git push`, is monitored, and can retrain and re-promote a model without you touching the server. At this point you can honestly call it an MLOps project.

---

## Phase 2 — Federated learning layer

**Where this runs, honestly:** your EC2 box has 1GB RAM. Phase 1's inference API + Prometheus already uses a meaningful chunk of that. Running an aggregator plus 3–4 training-capable client containers simultaneously will not fit. Build and develop Phase 2 in Docker Compose **on your own laptop**; treat it as something you spin up live for a demo or interview rather than something that stays hosted 24/7. Document this reasoning in your README — "here's what I'd change for a persistent multi-node cloud deployment" is a legitimate and honest thing to write, and it heads off the obvious interview question before it's asked.

### Week 8 — Federated learning fundamentals
- [ ] Session 1–2: Install Flower, work through its quickstart with a small toy model on 2 dummy clients using Flower's built-in simulation mode (single process) — this is purely to learn the API before touching your real model.
- [ ] Session 3: Decide the partitioning: your three existing datasets (NSL-KDD, UNSW-NB15, BoT-IoT) become three "organization" nodes. Note explicitly that they don't share identical feature schemas — pick a common feature subset across all three, or restrict the federated demo to two datasets that do align well. Don't skip this step; a federated demo that silently trains on mismatched features is worse than no demo.
- [ ] Session 4–6: Wire your actual Bi-LSTM model into a Flower client (local train/evaluate functions) and a Flower server (FedAvg strategy). Get 3 nodes running in Flower's simulation mode end to end.
- [ ] Session 7: Sanity-check: federated accuracy after a few rounds should be in the same ballpark as centralized training on the combined data (it won't match exactly — that's expected and fine to explain).

**Checkpoint:** federated averaging genuinely works on your real model and real data partitions, even if it's still single-process.

### Week 9 — Containerize it
- [ ] Session 1–2: Write a Dockerfile for the Flower server (aggregator) and one for the Flower client (parameterized by which dataset partition to load).
- [ ] Session 3–4: Write `docker-compose.federated.yml` — 1 aggregator + 3–4 client containers on a shared Docker network.
- [ ] Session 5–6: Get a real multi-container FedAvg round running over the Docker network (not Flower's in-process simulation) — this is meaningfully harder than Week 8 and where most of the debugging time will go.
- [ ] Session 7: Log each round's aggregate metrics to MLflow under a separate `federated-training` experiment, so you have real run history to show, not just a live demo that leaves no trace afterward.

**Checkpoint:** `docker compose -f docker-compose.federated.yml up` on your laptop produces a working multi-container federated training run, visible in MLflow.

### Week 10 — Integration and wrap-up
- [ ] Session 1–2: After N rounds, push the resulting global model into the MLflow registry as a new versioned model, reusing the same promotion-gate logic from Phase 1 Week 6.
- [ ] Session 3: Add basic per-node monitoring — track each client's local loss/accuracy per round; flag a node whose update magnitude is a statistical outlier relative to the others. State plainly that this is a lightweight stand-in for real Byzantine-robust aggregation, not a production security control.
- [ ] Session 4: Update the README/architecture doc for the full two-phase system. Explicitly tie this back to your original project pitch — the blockchain layer already claimed "cross-organization threat intelligence sharing" as a goal; federated learning is the actual technical mechanism that would let organizations improve a shared model without handing over raw traffic data. That's a genuinely good, coherent story if you tell it accurately.
- [ ] Session 5–6: Record the final demo.
- [ ] Session 7: Write a short, honest "simplifications" retrospective (see below) — this is worth the hour it costs.

**Phase 2 exit criteria:** a working, containerized, multi-node FedAvg demo, with run history in MLflow, that you can explain accurately end to end — including its limits.

---

## Simplifications to be upfront about

State these plainly in your README and out loud in interviews. Getting caught overclaiming costs you far more credibility than volunteering the caveat does:

- Labeling of "live" incoming traffic is simulated using held-out true labels from existing benchmark datasets, not a real analyst-in-the-loop labeling pipeline.
- The drift metric (PSI or similar) is a reasonable lightweight signal, not a full statistical monitoring suite.
- Federated node-outlier detection is magnitude-based, not real Byzantine-robust aggregation or differential privacy.
- The federated demo runs as multiple containers on one host, not genuinely separate machines/networks — the FedAvg mechanics are real, the network topology is simulated.
- NSL-KDD/UNSW-NB15 benchmark accuracy figures (99%+) are known in the literature to be inflated by dataset artifacts; be ready to discuss this rather than lead with the number.

## Stretch goals (only if ahead of schedule)

- [ ] Terraform for the EC2 instance + security group (Week 3 note above)
- [ ] A `/health` and `/ready` endpoint distinction, wired into a container healthcheck
- [ ] A basic load test (e.g. `locust` or `k6`) against the inference endpoint, results logged somewhere
- [ ] GitHub Actions status badge + Grafana dashboard screenshot embedded in the README

## Open questions to revisit once Phase 1 is underway

- Exact common feature subset across NSL-KDD/UNSW-NB15/BoT-IoT for the federated partitioning (Week 8) — worth a dedicated session once you're looking at the real schemas side by side.
- Whether to keep the EC2 box always-on for the full 10 weeks or stop/start it between sessions to conserve free-tier hours — free tier is 750 hrs/month, which covers one always-on instance, but check your actual usage once Prometheus is added.
