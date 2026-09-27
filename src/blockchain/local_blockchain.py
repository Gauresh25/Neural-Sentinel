"""
Local Blockchain — tamper-evident append-only log for Neural Sentinel alerts.

Each block contains:
  index       — position in chain
  timestamp   — Unix epoch (float)
  prev_hash   — SHA-256 of the previous block
  data        — alert payload (dict)
  hash        — SHA-256 of this block's contents

Persisted to a JSON file on disk.  Any post-hoc edit to a block breaks
every hash after it, which verify() will catch.
"""

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------


@dataclass
class Block:
    index: int
    timestamp: float
    prev_hash: str
    data: dict
    hash: str = ""

    def compute_hash(self) -> str:
        contents = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "prev_hash": self.prev_hash,
                "data": self.data,
            },
            sort_keys=True,
        )
        return hashlib.sha256(contents.encode()).hexdigest()


# ---------------------------------------------------------------------------
# LocalBlockchain
# ---------------------------------------------------------------------------


class LocalBlockchain:
    """Thread-safe append-only local blockchain."""

    GENESIS_DATA = {"event": "genesis", "msg": "Neural Sentinel chain initialised"}

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._chain: list[Block] = []

        if self.path.exists():
            self._load()
        else:
            self._create_genesis()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_block(self, data: dict) -> Block:
        """Append a new block. Returns the new block."""
        with self._lock:
            prev = self._chain[-1]
            block = Block(
                index=len(self._chain),
                timestamp=time.time(),
                prev_hash=prev.hash,
                data=data,
            )
            block.hash = block.compute_hash()
            self._chain.append(block)
            self._save()
        return block

    def verify(self) -> dict:
        """
        Walk the chain and verify every hash link.
        Returns {"valid": bool, "length": int, "broken_at": int | None}.
        """
        with self._lock:
            chain = list(self._chain)

        for i, block in enumerate(chain):
            # Re-compute expected hash
            expected = block.compute_hash()
            if block.hash != expected:
                return {
                    "valid": False,
                    "length": len(chain),
                    "broken_at": i,
                    "reason": "hash mismatch",
                }
            # Check prev_hash link (skip genesis)
            if i > 0 and block.prev_hash != chain[i - 1].hash:
                return {
                    "valid": False,
                    "length": len(chain),
                    "broken_at": i,
                    "reason": "broken link",
                }

        return {"valid": True, "length": len(chain), "broken_at": None}

    def to_list(self) -> list[dict]:
        with self._lock:
            return [asdict(b) for b in self._chain]

    def latest(self, n: int = 10) -> list[dict]:
        with self._lock:
            return [asdict(b) for b in self._chain[-n:]][::-1]

    def __len__(self) -> int:
        with self._lock:
            return len(self._chain)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _create_genesis(self) -> None:
        genesis = Block(
            index=0,
            timestamp=time.time(),
            prev_hash="0" * 64,
            data=self.GENESIS_DATA,
        )
        genesis.hash = genesis.compute_hash()
        self._chain = [genesis]
        self._save()

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps([asdict(b) for b in self._chain], indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.path)  # atomic on most OSes

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._chain = [Block(**b) for b in raw]
        print(f"[Blockchain] Loaded {len(self._chain)} blocks from {self.path}")
