FROM python:3.10-slim

# System deps: libpcap for scapy, build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libpcap0.8 \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY docker/sentinel/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy model and preprocessing artefacts
COPY models/bilstm_unsw_nb15.keras   /app/models/bilstm_unsw_nb15.keras
COPY data/processed/unsw-nb15/scaler.pkl    /app/data/processed/unsw-nb15/scaler.pkl
COPY data/processed/unsw-nb15/encoders.pkl  /app/data/processed/unsw-nb15/encoders.pkl
COPY data/processed/unsw-nb15/metadata.json /app/data/processed/unsw-nb15/metadata.json

# Copy application source
COPY src/ /app/src/

WORKDIR /app/src

ENV KERAS_BACKEND=torch
ENV KMP_DUPLICATE_LIB_OK=TRUE
ENV PYTHONUNBUFFERED=1
# Set SNIFF_IFACE to e.g. "eth0" if auto-detect fails
# ENV SNIFF_IFACE=eth0

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "inference_server:app", "--host", "0.0.0.0", "--port", "8000"]
