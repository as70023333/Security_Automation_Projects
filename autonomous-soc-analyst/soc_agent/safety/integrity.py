"""Code and policy integrity.

* ``admin seal`` writes ``integrity.lock``: SHA-256 of every agent source file plus the
  IR and safety policies. Commit it / keep it read-only for the service account.
* At startup the agent verifies itself against the manifest (live mode refuses to act
  without a valid one), then re-hashes periodically and before every action batch.
  Any drift engages the kill switch (full stop) and alerts the admin.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def tracked_files(policy_paths: list[str | Path]) -> list[Path]:
    files = sorted(p for p in PACKAGE_DIR.rglob("*.py") if "__pycache__" not in p.parts)
    for extra in policy_paths:
        p = Path(extra).resolve()
        if p.exists():
            files.append(p)
    return files


def _key(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.resolve().as_posix()


class IntegrityMonitor:
    def __init__(self, files: list[Path], root: Path | None = None) -> None:
        self.root = (root or PACKAGE_DIR.parent).resolve()
        self.files = [f.resolve() for f in files]
        self.baseline = self.snapshot()

    def snapshot(self) -> dict[str, str | None]:
        return {_key(f, self.root): _sha256(f) for f in self.files}

    def drift(self) -> list[str]:
        """Files whose content changed (or vanished) since the agent started."""
        now = self.snapshot()
        return sorted(k for k, v in self.baseline.items() if now.get(k) != v)

    def verify_manifest(self, manifest_path: str | Path) -> tuple[bool, list[str]]:
        p = Path(manifest_path)
        if not p.exists():
            return False, ["integrity manifest not found (run: python -m soc_agent admin seal)"]
        try:
            manifest = json.loads(p.read_text(encoding="utf-8"))
            expected: dict[str, str] = manifest["files"]
        except (ValueError, KeyError, TypeError):
            return False, ["integrity manifest is unreadable"]
        problems = []
        for key, digest in self.baseline.items():
            if key not in expected:
                problems.append(f"{key}: not in sealed manifest (new file)")
            elif expected[key] != digest:
                problems.append(f"{key}: hash differs from sealed manifest")
        for key in expected:
            if key not in self.baseline:
                problems.append(f"{key}: sealed file missing")
        return not problems, problems


def write_manifest(manifest_path: str | Path, files: list[Path], root: Path | None = None) -> int:
    base = (root or PACKAGE_DIR.parent).resolve()
    digests = {_key(f, base): _sha256(f) for f in files}
    Path(manifest_path).write_text(
        json.dumps({"version": 1, "files": digests}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return len(digests)
