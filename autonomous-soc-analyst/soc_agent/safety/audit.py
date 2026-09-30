"""Tamper-evident, append-only audit log (hash-chained JSON lines).

Every safety decision, action and admin operation is written here. Each line embeds the
hash of the previous line, so deleting or editing any entry breaks the chain, which
``python -m soc_agent admin verify-audit`` detects. Ship this file to your SIEM (or a
WORM bucket) so the agent's own record of itself lives somewhere it cannot reach.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from ..models import utcnow
from ..utils import iso

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(body).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last: str | None = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        try:
            entry = json.loads(last)
            return int(entry["seq"]), str(entry["hash"])
        except (ValueError, KeyError, TypeError):
            # A corrupt tail is itself evidence of tampering; start a new, linked segment.
            return 0, "corrupt-tail"

    def append(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "seq": self._seq + 1,
                "ts": iso(utcnow()),
                "type": event_type,
                "data": data,
                "prev": self._prev,
            }
            entry["hash"] = _digest(entry)
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq = entry["seq"]
            self._prev = entry["hash"]
            return entry

    async def aappend(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(self.append, event_type, data)

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"type": "corrupt_line", "raw": line[:200]})
        return out


def verify_audit_log(path: str | Path) -> tuple[bool, int, str]:
    """Return (ok, entries_checked, message)."""
    p = Path(path)
    if not p.exists():
        return True, 0, "audit log does not exist yet"
    prev = GENESIS
    expected_seq = 1
    count = 0
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False, count, f"line {lineno}: not valid JSON"
            claimed = entry.pop("hash", None)
            if entry.get("prev") != prev:
                return False, count, f"line {lineno}: chain broken (entry removed, reordered or edited before it)"
            if entry.get("seq") != expected_seq:
                return False, count, f"line {lineno}: sequence gap (expected {expected_seq}, got {entry.get('seq')})"
            if _digest(entry) != claimed:
                return False, count, f"line {lineno}: content hash mismatch (entry edited)"
            prev = str(claimed)
            expected_seq += 1
            count += 1
    return True, count, f"{count} entries verified; chain intact"
