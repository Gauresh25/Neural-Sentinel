FROM python:3.10-slim

# System deps: libpcap for scapy, openssh-server for SSH brute-force demo target
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libpcap0.8 \
    gcc \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# ── SSH demo target (port 2222) ───────────────────────────────────────────────
# Intentionally weak credentials so hydra brute-force demo works end-to-end.
# The correct password is at position 10 of /wordlist_ssh.txt so hydra makes
# enough failed attempts (≥5) before succeeding, triggering the heuristic.
RUN useradd -m -s /bin/bash demo_user \
 && echo "demo_user:s3ntinel_brute" | chpasswd \
 && echo "root:toor" | chpasswd

RUN mkdir -p /run/sshd \
 && sed -i 's/#Port 22/Port 2222/'                          /etc/ssh/sshd_config \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && echo "PermitRootLogin yes"   >> /etc/ssh/sshd_config \
 && echo "MaxAuthTries 100"      >> /etc/ssh/sshd_config

WORKDIR /app

# PyTorch CPU-only — must be installed before keras (which imports torch at build time).
# The default PyPI index serves the CUDA wheel (~2.5 GB); the whl.cpu index is ~200 MB.
RUN pip install --no-cache-dir \
    torch==2.5.1+cpu \
    --index-url https://download.pytorch.org/whl/cpu

# Remaining deps (keras, fastapi, scapy, …)
COPY docker/sentinel/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy model and preprocessing artefacts
COPY models/bilstm_unsw_nb15.keras                  /app/models/bilstm_unsw_nb15.keras
COPY data/processed/unsw-nb15/scaler.pkl            /app/data/processed/unsw-nb15/scaler.pkl
COPY data/processed/unsw-nb15/encoders.pkl          /app/data/processed/unsw-nb15/encoders.pkl
COPY data/processed/unsw-nb15/metadata.json         /app/data/processed/unsw-nb15/metadata.json

# Copy application source + startup script
COPY src/                       /app/src/
COPY docker/sentinel/start.sh   /start.sh
RUN chmod +x /start.sh

WORKDIR /app/src

ENV KERAS_BACKEND=torch
ENV KMP_DUPLICATE_LIB_OK=TRUE
ENV PYTHONUNBUFFERED=1

EXPOSE 8000 2222

CMD ["/start.sh"]
