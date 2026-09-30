"""Runtime breakout guard (Python audit hook, PEP 578).

Once installed it cannot be removed for the life of the process. It watches for things
a Tier-1 SOC agent never legitimately does, blocks them, and reports them:

  * spawning a process / shell (``subprocess``, ``os.system``, ``exec*``, ``spawn*``, ``fork``)
      -> PROCESS_SPAWN_ATTEMPT   (e.g. "pip install", "systemctl restart", reverse shell)
  * writing to its own source code or policy files
      -> SELF_MODIFICATION
  * deleting / renaming / overwriting / chmod-ing its kill switch file
      -> SELF_HEAL_ATTEMPT       (trying to switch itself back on)
  * truncating / deleting / renaming the audit log
      -> AUDIT_TAMPER_ATTEMPT

This is defence in depth. Real enforcement belongs at the OS layer as well: run as an
unprivileged user, read-only root filesystem, code owned by root, no shell in the image.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from .events import EventKind
from .killswitch import KILL_FILE_WRITE_ALLOWED

PROCESS_EVENTS = frozenset(
    {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "pty.spawn"}
)
DELETE_EVENTS = frozenset({"os.remove", "os.rmdir", "shutil.rmtree"})
MODIFY_EVENTS = frozenset({"os.chmod", "os.chown", "os.truncate", "os.utime", "os.chflags"})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

Reporter = Callable[[EventKind, str, dict[str, Any]], None]

_INSTALLED: "RuntimeGuard | None" = None
_LOCK = threading.Lock()


class RuntimeGuard:
    def __init__(
        self,
        *,
        protected_dirs: list[Path],
        protected_files: list[Path],
        kill_file: Path,
        append_only_files: list[Path],
        reporter: Reporter,
        block_process_spawn: bool = True,
    ) -> None:
        self.protected_dirs = [self._real(p) for p in protected_dirs]
        self.protected_files = {self._real(p) for p in protected_files}
        self.kill_file = self._real(kill_file)
        self.append_only = {self._real(p) for p in append_only_files}
        self.reporter = reporter
        self.block_process_spawn = block_process_spawn
        self._local = threading.local()
        self.blocked = 0

    @staticmethod
    def _real(path: Any) -> str:
        return os.path.realpath(os.fspath(path))

    def install(self) -> bool:
        """Install once per process. Returns False if a guard is already active."""
        global _INSTALLED
        with _LOCK:
            if _INSTALLED is not None:
                return False
            _INSTALLED = self
            sys.addaudithook(self._hook)
            return True

    # ------------------------------------------------------------------ helpers

    def _path(self, value: Any) -> str | None:
        if isinstance(value, int) or value is None:
            return None
        try:
            return os.path.realpath(os.fsdecode(os.fspath(value)))
        except (TypeError, ValueError):
            return None

    def _in_code(self, path: str) -> bool:
        if f"{os.sep}__pycache__{os.sep}" in path or path.endswith((".pyc", ".pyo")):
            return False  # bytecode cache is not source
        return path in self.protected_files or any(
            path == d or path.startswith(d + os.sep) for d in self.protected_dirs
        )

    def _deny(self, kind: EventKind, message: str, detail: dict[str, Any]) -> None:
        self.blocked += 1
        self._local.active = True
        try:
            self.reporter(kind, message, detail)
        finally:
            self._local.active = False
        raise PermissionError(errno.EACCES, f"SOC agent safety guard: {message}")

    # ------------------------------------------------------------------ hook

    def _hook(self, event: str, args: tuple[Any, ...]) -> None:
        if getattr(self._local, "active", False):
            return
        if event in PROCESS_EVENTS:
            if self.block_process_spawn:
                exe = args[0] if args else None
                self._deny(EventKind.PROCESS_SPAWN_ATTEMPT, f"process spawn blocked ({event})",
                           {"event": event, "executable": str(exe)[:200]})
            return
        if event == "open":
            self._check_open(args)
        elif event in DELETE_EVENTS:
            self._check_destructive(event, self._path(args[0] if args else None))
        elif event == "os.rename":
            for p in args[:2]:
                self._check_destructive(event, self._path(p))
        elif event in MODIFY_EVENTS:
            path = self._path(args[0] if args else None)
            if path and (path == self.kill_file or path in self.append_only or self._in_code(path)):
                self._check_destructive(event, path)
        elif event in ("os.link", "os.symlink"):
            self._check_destructive(event, self._path(args[1] if len(args) > 1 else None))

    def _check_open(self, args: tuple[Any, ...]) -> None:
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else None
        if isinstance(flags, int):
            writing = bool(flags & _WRITE_FLAGS)
            truncating = bool(flags & os.O_TRUNC)
        elif isinstance(mode, str):
            writing = any(c in mode for c in "wax+")
            truncating = "w" in mode
        else:
            return
        if not writing:
            return
        path = self._path(args[0] if args else None)
        if path is None:
            return
        if path == self.kill_file:
            if not KILL_FILE_WRITE_ALLOWED.get():
                self._deny(EventKind.SELF_HEAL_ATTEMPT, "attempt to overwrite the kill switch file",
                           {"path": path, "mode": str(mode)})
            return
        if path in self.append_only:
            if truncating:
                self._deny(EventKind.AUDIT_TAMPER_ATTEMPT, "attempt to truncate the audit log", {"path": path})
            return
        if self._in_code(path):
            self._deny(EventKind.SELF_MODIFICATION, "attempt to write to agent code/policy",
                       {"path": path, "mode": str(mode)})

    def _check_destructive(self, event: str, path: str | None) -> None:
        if path is None:
            return
        if path == self.kill_file:
            self._deny(EventKind.SELF_HEAL_ATTEMPT, f"attempt to remove/alter the kill switch file ({event})",
                       {"path": path, "event": event})
        if path in self.append_only:
            self._deny(EventKind.AUDIT_TAMPER_ATTEMPT, f"attempt to remove/alter the audit log ({event})",
                       {"path": path, "event": event})
        if self._in_code(path) or any(d.startswith(path + os.sep) for d in self.protected_dirs):
            self._deny(EventKind.SELF_MODIFICATION, f"attempt to modify agent code/policy ({event})",
                       {"path": path, "event": event})


def installed_guard() -> RuntimeGuard | None:
    return _INSTALLED
