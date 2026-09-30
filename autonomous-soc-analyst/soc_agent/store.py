"""SQLite persistence: cases, alert de-duplication, action log and a small key/value table."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import ActionRecord, Case, utcnow
from .utils import iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_key TEXT PRIMARY KEY,
    case_id   TEXT NOT NULL,
    received  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    title       TEXT NOT NULL,
    alert_class TEXT NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    routing     TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at);
CREATE TABLE IF NOT EXISTS action_log (
    id        TEXT PRIMARY KEY,
    case_id   TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    status    TEXT NOT NULL,
    ts        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_log ON action_log(action, ts);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class CaseStore:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()

    def _run(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.rowcount

    async def claim_alert(self, alert_key: str, case_id: str) -> str | None:
        """Atomically claim an alert. Returns the existing case id if it was already processed."""
        inserted = await asyncio.to_thread(
            self._write, "INSERT OR IGNORE INTO alerts(alert_key, case_id, received) VALUES (?, ?, ?)",
            (alert_key, case_id, iso(utcnow())),
        )
        if inserted:
            return None
        rows = await asyncio.to_thread(self._run, "SELECT case_id FROM alerts WHERE alert_key = ?", (alert_key,))
        return rows[0]["case_id"] if rows else None

    async def save_case(self, case: Case) -> None:
        data = case.model_dump_json()
        await asyncio.to_thread(
            self._write,
            """INSERT INTO cases(id, created_at, updated_at, title, alert_class, severity, status, verdict, routing, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at, alert_class=excluded.alert_class,
                 severity=excluded.severity, status=excluded.status, verdict=excluded.verdict,
                 routing=excluded.routing, data=excluded.data""",
            (case.id, iso(case.started_at), iso(utcnow()), case.alert.title, case.alert_class, case.severity.value,
             case.status.value, case.verdict.value, case.routing.value, data),
        )

    async def get_case(self, case_id: str) -> Case | None:
        rows = await asyncio.to_thread(self._run, "SELECT data FROM cases WHERE id = ?", (case_id,))
        return Case.model_validate_json(rows[0]["data"]) if rows else None

    async def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = await asyncio.to_thread(
            self._run,
            "SELECT id, created_at, title, alert_class, severity, status, verdict, routing FROM cases "
            "ORDER BY created_at DESC LIMIT ?",
            (max(1, min(500, limit)),),
        )
        return [dict(r) for r in rows]

    async def log_action(self, case_id: str, record: ActionRecord) -> None:
        await asyncio.to_thread(
            self._write,
            "INSERT OR REPLACE INTO action_log(id, case_id, action, target, status, ts) VALUES (?, ?, ?, ?, ?, ?)",
            (record.id, case_id, record.action.value, record.target, record.status.value,
             iso(record.finished_at or utcnow())),
        )

    async def count_actions_since(self, action: str, since: datetime, statuses: list[str]) -> int:
        marks = ",".join("?" for _ in statuses)
        rows = await asyncio.to_thread(
            self._run,
            f"SELECT COUNT(*) AS n FROM action_log WHERE action = ? AND ts >= ? AND status IN ({marks})",
            (action, iso(since), *statuses),
        )
        return int(rows[0]["n"]) if rows else 0

    async def get_kv(self, key: str) -> str | None:
        rows = await asyncio.to_thread(self._run, "SELECT value FROM kv WHERE key = ?", (key,))
        return rows[0]["value"] if rows else None

    async def set_kv(self, key: str, value: str) -> None:
        await asyncio.to_thread(
            self._write, "INSERT INTO kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    async def list_kv(self, prefix: str) -> list[tuple[str, str]]:
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = await asyncio.to_thread(
            self._run, "SELECT key, value FROM kv WHERE key LIKE ? ESCAPE '\\' ORDER BY key", (escaped + "%",)
        )
        return [(r["key"], r["value"]) for r in rows]

    async def delete_kv(self, key: str) -> None:
        await asyncio.to_thread(self._write, "DELETE FROM kv WHERE key = ?", (key,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
