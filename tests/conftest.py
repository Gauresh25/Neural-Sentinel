import sys
from pathlib import Path

# src/api/inference_server.py imports its siblings as top-level packages
# (`from streaming.stream_processor import ...`), matching how it's run in
# Docker (WORKDIR /app/src). Put src/ on sys.path so tests import it the same way.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
