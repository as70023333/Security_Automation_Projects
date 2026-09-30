"""Small, dependency-free helpers shared across the agent."""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Any

_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def normalize_hash(value: Any) -> tuple[str, str] | None:
    """Return (algorithm, lowercase hex) for md5/sha1/sha256 strings, else None."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    algo = _HASH_LENGTHS.get(len(text))
    if algo is None or not _HEX.match(text):
        return None
    return algo, text


def is_hex_hash(value: str) -> bool:
    return normalize_hash(value) is not None


def parse_ip(value: Any) -> str | None:
    """Normalise an IP string (strips ports like '1.2.3.4:443'); None if invalid."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    # IPv4 with port, or [v6]:port
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_public_ip(value: str, *, allow_documentation: bool = False) -> bool:
    """True only for globally routable unicast addresses.

    ``allow_documentation`` lets simulations use the RFC 5737 test ranges as if
    they were internet addresses; it is never enabled outside mock mode.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    if allow_documentation and any(ip in net for net in _DOC_NETS):
        return True
    return ip.is_global


def odata_str(value: str) -> str:
    """Escape a value for use inside a single-quoted OData string literal."""
    return value.replace("'", "''")


def kql_str(value: str) -> str:
    """Escape a value for use inside a double-quoted KQL string literal."""
    cleaned = value.replace("\r", " ").replace("\n", " ")
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def parse_dt(value: Any) -> datetime | None:
    """Parse ISO-8601 timestamps (incl. 'Z' and 7-digit fractions) to aware UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    # Trim fractional seconds beyond microseconds (Microsoft emits 7 digits).
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", text)
    if match:
        text = f"{match.group(1)}.{match.group(2)[:6].ljust(6, '0')}{match.group(3)}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    """Fixed-width ISO format so stored timestamps sort lexicographically."""
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def dedupe(items: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    out: list[Any] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


class Deadline:
    """Tracks the remaining time inside the end-to-end SLA budget."""

    def __init__(self, total_seconds: float) -> None:
        self.total = float(total_seconds)
        self._start = time.monotonic()

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def remaining(self) -> float:
        return self.total - self.elapsed()

    def budget(self, *, reserve: float, cap: float) -> float:
        """Time available for a phase while keeping ``reserve`` for later phases."""
        return max(0.0, min(cap, self.remaining() - reserve))
