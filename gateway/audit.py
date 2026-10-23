"""Append-only JSONL audit log with SHA-256 hash chaining.

Every record carries ``seq``, ``prev_hash`` and ``hash`` where::

    hash = sha256(prev_hash + canonical_json(record_without_hash))

Editing, deleting or reordering any line breaks the chain from that point on,
which ``verify`` reports with the offending sequence number. Records never
contain raw prompt text or raw secrets - only lengths, decisions, rule names
and masked previews - so the log itself is not a data-leak channel.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


def canonical(record: dict[str, Any]) -> str:
    """Deterministic JSON serialisation used for hashing."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """Hash a record (without its ``hash`` field) chained to ``prev_hash``."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256((prev_hash + canonical(body)).encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    """Outcome of a chain verification."""

    ok: bool
    records: int
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    """Thread-safe append-only writer."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._tail()

    def _tail(self) -> tuple[int, str]:
        """Resume the chain from an existing file (so restarts keep one chain)."""
        if not self.path.exists():
            return 0, GENESIS
        last: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)
                    except json.JSONDecodeError:
                        continue
        if not last:
            return 0, GENESIS
        return int(last.get("seq", 0)), str(last.get("hash", GENESIS))

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        """Write one chained record and return it."""
        with self._lock:
            record: dict[str, Any] = {
                "seq": self._seq + 1,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "event": event,
                **fields,
                "prev_hash": self._last_hash,
            }
            record["hash"] = compute_hash(self._last_hash, record)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(canonical(record) + "\n")
            self._seq = record["seq"]
            self._last_hash = record["hash"]
            return record

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the last ``limit`` records."""
        return list(iter_records(self.path))[-limit:]


def iter_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield parsed records from a JSONL file (malformed lines are yielded as errors)."""
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                yield {"_malformed_line": n}


def verify(path: str | Path) -> VerifyResult:
    """Recompute the chain and report the first broken link."""
    prev = GENESIS
    expected_seq = 1
    count = 0
    for rec in iter_records(path):
        if "_malformed_line" in rec:
            return VerifyResult(False, count, expected_seq, f"malformed JSON on line {rec['_malformed_line']}")
        count += 1
        seq = rec.get("seq")
        if seq != expected_seq:
            return VerifyResult(False, count, expected_seq, f"sequence gap: expected {expected_seq}, found {seq}")
        if rec.get("prev_hash") != prev:
            return VerifyResult(False, count, seq, "prev_hash does not match previous record (reorder/delete)")
        if compute_hash(prev, rec) != rec.get("hash"):
            return VerifyResult(False, count, seq, "record hash mismatch (content modified)")
        prev = str(rec["hash"])
        expected_seq += 1
    return VerifyResult(True, count)
