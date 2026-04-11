"""
Neural Sentinel — Inference Server
FastAPI app that:
  - loads the Bi-LSTM model at startup
  - runs the stream processor in a background thread
  - serves a live dashboard at GET /dashboard
  - streams alerts via Server-Sent Events at GET /alerts
  - exposes POST /predict for manual testing
"""

import os
import asyncio
import json
import threading
import time
from collections import deque
from pathlib import Path

# Set backend BEFORE keras import
os.environ.setdefault("KERAS_BACKEND", "torch")
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel

import keras

from stream_processor import StreamProcessor

ROOT = Path(__file__).parent.parent
MODEL_PATH = ROOT / "models" / "bilstm_unsw_nb15.keras"
DASHBOARD_PATH = Path(__file__).parent / "dashboard.html"

app = FastAPI(title="Neural Sentinel")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_model: keras.Model = None
_alert_queue: asyncio.Queue = None
_loop: asyncio.AbstractEventLoop = None
_recent_alerts: deque = deque(maxlen=50)
_stats = {"total": 0, "attacks": 0, "normal": 0, "start_time": time.time()}


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup():
    global _model, _alert_queue, _loop

    print(f"[Sentinel] Loading model from {MODEL_PATH}")
    _model = keras.models.load_model(str(MODEL_PATH))
    print("[Sentinel] Model loaded.")

    _alert_queue = asyncio.Queue()
    _loop = asyncio.get_event_loop()

    # Start stream processor in background thread
    iface = os.environ.get("SNIFF_IFACE", None)  # e.g. "eth0"
    proc = StreamProcessor(on_prediction=_handle_prediction, iface=iface)
    t = threading.Thread(target=proc.start, daemon=True)
    t.start()
    print("[Sentinel] Stream processor started.")


# ---------------------------------------------------------------------------
# Core prediction
# ---------------------------------------------------------------------------

def _handle_prediction(sequence: np.ndarray, raws: list) -> None:
    """Called from stream processor thread. Posts result to asyncio queue."""
    batch = sequence[np.newaxis, ...]           # (1, 10, 44)
    prob = float(_model.predict(batch, verbose=0).squeeze())
    label = int(prob >= 0.5)
    attack_type = StreamProcessor.heuristic_attack_type(raws) if label else "Normal"

    last_raw = raws[-1]
    alert = {
        "time": time.strftime("%H:%M:%S"),
        "src": last_raw.get("src_ip", "?"),
        "dst": last_raw.get("dst_ip", "?"),
        "proto": last_raw.get("proto", "?"),
        "service": last_raw.get("service", "-"),
        "label": label,
        "confidence": round(prob, 4),
        "attack_type": attack_type,
    }

    _stats["total"] += 1
    if label:
        _stats["attacks"] += 1
    else:
        _stats["normal"] += 1

    _recent_alerts.appendleft(alert)

    # Thread-safe push to asyncio queue
    asyncio.run_coroutine_threadsafe(_alert_queue.put(alert), _loop)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

class Sequence(BaseModel):
    sequence: list  # 10 × 44 nested list


@app.post("/predict")
async def predict(body: Sequence):
    """Manual test endpoint — POST a pre-built sequence."""
    seq = np.array(body.sequence, dtype=np.float32)
    if seq.shape != (10, 44):
        return JSONResponse({"error": f"Expected (10,44), got {seq.shape}"}, status_code=400)
    batch = seq[np.newaxis, ...]
    prob = float(_model.predict(batch, verbose=0).squeeze())
    return {"label": int(prob >= 0.5), "confidence": round(prob, 4)}


@app.get("/alerts")
async def alerts():
    """Server-Sent Events stream of live detections."""
    async def event_stream():
        while True:
            alert = await _alert_queue.get()
            yield f"data: {json.dumps(alert)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/recent")
async def recent():
    return list(_recent_alerts)


@app.get("/stats")
async def stats():
    elapsed = time.time() - _stats["start_time"]
    return {
        **_stats,
        "elapsed_s": round(elapsed, 1),
        "attack_rate": round(_stats["attacks"] / max(elapsed / 60, 0.01), 2),
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_PATH.read_text(encoding="utf-8")


@app.get("/")
async def root():
    return HTMLResponse('<meta http-equiv="refresh" content="0; url=/dashboard">')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("inference_server:app", host="0.0.0.0", port=8000, reload=False)
