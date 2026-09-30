"""The kill switch.

Three independent ways to stop the agent, any one of which wins:
  1. The kill file exists            (``touch data/KILL_SWITCH`` or ``admin kill``)
  2. ``SOC_KILL_SWITCH=true``        (environment, e.g. from your orchestrator)
  3. ``POST /admin/kill``            (admin API key; writes the kill file)

Properties:
  * Fail-closed: an unreadable or malformed kill file counts as ENGAGED (full stop).
  * One-way from inside: the agent process can engage the switch but has no code path
    to clear it, and the runtime guard blocks it from deleting/renaming/overwriting the
    kill file. Only an admin, from outside the process, can clear it (``admin resume``).
  * Checked immediately before every single action, not cached.
  * Levels: ``actions`` = no changes to any system (investigation + reports continue,
    humans are paged for anything that needed containment); ``full`` = stop processing
    alerts entirely (webhooks return 503 so the SIEM retries later).
"""

from __future__ import annotations

import contextvars
import json
import os
import socket
import threading
from enum import Enum
from pathlib import Path
from typing import Callable

from pydantic import BaseModel

from ..models import utcnow
from ..utils import iso

# Set only while KillSwitch.engage() writes the kill file (checked by the runtime guard).
KILL_FILE_WRITE_ALLOWED: contextvars.ContextVar[bool] = contextvars.ContextVar("kill_file_write", default=False)


class KillLevel(str, Enum):
    ACTIONS = "actions"
    FULL = "full"


class KillState(BaseModel):
    engaged: bool
    level: KillLevel | None = None
    reason: str = ""
    engaged_by: str = ""
    engaged_at: str = ""
    source: str = ""  # file | env | latched | fail-closed

    @property
    def halts_actions(self) -> bool:
        return self.engaged

    @property
    def halts_processing(self) -> bool:
        return self.engaged and self.level == KillLevel.FULL


class KillSwitch:
    def __init__(self, path: str | Path, *, env_engaged: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._env = env_engaged
        self._latched: KillState | None = None
        self._lock = threading.Lock()
        self._listeners: list[Callable[[KillState], None]] = []

    def add_listener(self, fn: Callable[[KillState], None]) -> None:
        self._listeners.append(fn)

    def state(self) -> KillState:
        if self._env:
            return KillState(engaged=True, level=KillLevel.FULL, reason="SOC_KILL_SWITCH environment variable is set",
                             source="env")
        if self._latched is not None:
            return self._latched
        try:
            if not self.path.exists():
                return KillState(engaged=False)
            raw = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            return KillState(engaged=True, level=KillLevel.FULL, reason=f"kill file unreadable ({exc.strerror})",
                             source="fail-closed")
        try:
            data = json.loads(raw) if raw.strip() else {}
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return KillState(engaged=True, level=KillLevel.FULL, reason="kill file present (unstructured content)",
                             source="file")
        try:
            level = KillLevel(data.get("level", KillLevel.FULL.value))
        except ValueError:
            level = KillLevel.FULL
        return KillState(
            engaged=True,
            level=level,
            reason=str(data.get("reason") or "kill file present"),
            engaged_by=str(data.get("engaged_by") or ""),
            engaged_at=str(data.get("engaged_at") or ""),
            source="file",
        )

    @property
    def engaged(self) -> bool:
        return self.state().engaged

    def engage(self, level: KillLevel, reason: str, engaged_by: str) -> KillState:
        """Engage (or escalate) the kill switch. Never downgrades FULL to ACTIONS."""
        with self._lock:
            current = self.state()
            if current.engaged and current.level == KillLevel.FULL:
                level = KillLevel.FULL
            if current.engaged and current.level == level and current.source == "file":
                return current
            state = KillState(
                engaged=True, level=level, reason=reason, engaged_by=engaged_by,
                engaged_at=iso(utcnow()), source="file",
            )
            payload = {
                "level": level.value,
                "reason": reason,
                "engaged_by": engaged_by,
                "engaged_at": state.engaged_at,
                "host": socket.gethostname(),
                "pid": os.getpid(),
            }
            token = KILL_FILE_WRITE_ALLOWED.set(True)
            try:
                with self.path.open("w", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload, indent=2))
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                # Could not persist: latch in memory so this process stays halted anyway.
                state = state.model_copy(update={"source": "latched", "reason": f"{reason} (kill file write "
                                                                                  f"failed: {exc.strerror})"})
                self._latched = state
            finally:
                KILL_FILE_WRITE_ALLOWED.reset(token)
        for fn in list(self._listeners):
            try:
                fn(state)
            except Exception:  # listeners must never prevent the kill
                pass
        return state


def clear_kill_file(path: str | Path) -> bool:
    """Admin-only: remove the kill file. Called by the ``admin resume`` CLI, which runs as a
    separate process without the runtime guard. The server process never calls this."""
    p = Path(path)
    if p.exists():
        p.unlink()
        return True
    return False
