"""Safety monitor: receives security events, trips the kill switch, alerts the admin.

Events can come from any thread (the runtime audit hook fires synchronously), so
``report`` only does thread-safe work: it trips the kill switch immediately (no waiting
for the event loop) and queues the event. An async loop drains the queue into the audit
log and the admin's out-of-band channel, and runs the periodic integrity check and the
kill-switch state watcher.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import socket
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx

from ..config import Settings
from ..connectors.http import request
from ..models import Severity, utcnow
from ..utils import iso, parse_dt
from .audit import AuditLog
from .events import EVENT_EXPLANATIONS, EventKind, SafetyPolicy, SecurityEvent
from .integrity import IntegrityMonitor
from .killswitch import KillLevel, KillState, KillSwitch

log = logging.getLogger("soc_agent.safety")

PD_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFORMATIONAL: "info",
}


class AdminAlerter:
    """Out-of-band channel to the platform admin (NOT the SOC on-call channels)."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None, fallback_path: Path) -> None:
        self.settings = settings
        self.client = client
        self.fallback_path = fallback_path
        self.sent: list[dict[str, Any]] = []  # in-memory record (also used by tests / status API)

    @property
    def configured(self) -> bool:
        return bool(self.settings.admin_webhook_url or self.settings.secret("admin_pagerduty_routing_key"))

    async def send(self, event: SecurityEvent, kill: KillState) -> list[str]:
        title = f"SOC AGENT SAFETY ALERT: {event.kind.value.replace('_', ' ').upper()}"
        explanation = EVENT_EXPLANATIONS.get(event.kind, "")
        kill_line = (
            f"Kill switch ENGAGED ({kill.level.value if kill.level else 'full'}): {kill.reason}"
            if kill.engaged else "Kill switch not engaged"
        )
        body_lines = [event.summary, explanation, kill_line,
                      f"Host: {socket.gethostname()} | PID {os.getpid()} | {iso(event.ts)}"]
        if event.case_id:
            body_lines.append(f"Case: {event.case_id}")
        if event.detail:
            body_lines.append("Detail: " + json.dumps(event.detail, default=str)[:800])
        if kill.engaged:
            body_lines.append("To resume after review: python -m soc_agent admin resume --confirm")
        text = "\n".join(line for line in body_lines if line)
        record = {"title": title, "text": text, "kind": event.kind.value, "severity": event.severity.value}
        self.sent.append(record)
        del self.sent[:-200]
        results: list[str] = []
        if self.client is not None and self.settings.admin_webhook_url:
            results.append(await self._webhook(title, text, event))
        if self.client is not None and self.settings.secret("admin_pagerduty_routing_key"):
            results.append(await self._pagerduty(title, text, event))
        if not results or all(not r.endswith(": sent") for r in results):
            self._fallback(record)
            results.append("fallback: written to admin alert file")
        log.critical("%s | %s", title, event.summary)
        return results

    async def _webhook(self, title: str, text: str, event: SecurityEvent) -> str:
        fmt = self.settings.admin_webhook_format
        if fmt == "teams":
            payload: dict[str, Any] = {"type": "message", "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "body": [
                                {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Large",
                                 "color": "Attention", "wrap": True},
                                {"type": "TextBlock", "text": text, "wrap": True}]}}]}
        elif fmt == "slack":
            payload = {"text": f"*{title}*\n{text}"}
        else:
            payload = {"title": title, "text": text, "event": event.model_dump(mode="json")}
        try:
            assert self.client is not None and self.settings.admin_webhook_url
            await request(self.client, "POST", self.settings.admin_webhook_url, service="admin webhook",
                          json_body=payload, timeout=5.0, retries=1, expected=(200, 201, 202, 204))
            return "admin webhook: sent"
        except Exception as exc:  # delivery failure must never crash the monitor
            return f"admin webhook: FAILED ({exc})"

    async def _pagerduty(self, title: str, text: str, event: SecurityEvent) -> str:
        try:
            assert self.client is not None
            await request(self.client, "POST", "https://events.pagerduty.com/v2/enqueue", service="admin PagerDuty",
                          json_body={
                              "routing_key": self.settings.secret("admin_pagerduty_routing_key"),
                              "event_action": "trigger",
                              "dedup_key": f"soc-agent-safety-{event.kind.value}",
                              "payload": {"summary": f"{title}: {event.summary}"[:1000],
                                          "source": socket.gethostname(),
                                          "severity": PD_SEVERITY[event.severity],
                                          "custom_details": {"text": text}},
                          }, timeout=5.0, retries=1, expected=(200, 202))
            return "admin PagerDuty: sent"
        except Exception as exc:
            return f"admin PagerDuty: FAILED ({exc})"

    def _fallback(self, record: dict[str, Any]) -> None:
        try:
            self.fallback_path.parent.mkdir(parents=True, exist_ok=True)
            with self.fallback_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": iso(utcnow()), **record}) + "\n")
        except OSError:
            log.critical("could not write admin alert fallback file %s", self.fallback_path)


class SafetyMonitor:
    def __init__(
        self,
        *,
        settings: Settings,
        policy: SafetyPolicy,
        kill_switch: KillSwitch,
        audit: AuditLog,
        alerter: AdminAlerter,
        integrity: IntegrityMonitor | None,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.kill_switch = kill_switch
        self.audit = audit
        self.alerter = alerter
        self.integrity = integrity
        self._queue: queue.SimpleQueue[SecurityEvent] = queue.SimpleQueue()
        self._recent_alerts: dict[str, float] = {}
        self._failures: list[float] = []
        self._task: asyncio.Task[None] | None = None
        self._last_kill: KillState = kill_switch.state()
        self.events: list[SecurityEvent] = []

    # ------------------------------------------------------------------ reporting (thread-safe)

    def report(
        self,
        kind: EventKind,
        summary: str,
        detail: dict[str, Any] | None = None,
        *,
        case_id: str | None = None,
        severity: Severity = Severity.HIGH,
        force_trip: bool = False,
    ) -> SecurityEvent:
        event = SecurityEvent(kind=kind, severity=severity, summary=summary, detail=detail or {}, case_id=case_id)
        if force_trip or kind in self.policy.trip_on:
            level = KillLevel.FULL if kind in self.policy.full_stop_on else KillLevel.ACTIONS
            self.kill_switch.engage(level, f"auto-tripped: {kind.value}: {summary}"[:500], "safety-monitor")
            event.tripped_kill_switch = True
        self._queue.put(event)
        return event

    def egress_violation(self, host: str, target: str) -> None:
        self.report(EventKind.EGRESS_VIOLATION, f"blocked outbound request to {host}", {"target": target},
                    severity=Severity.CRITICAL)

    def runtime_violation(self, kind: EventKind, message: str, detail: dict[str, Any]) -> None:
        self.report(kind, message, detail, severity=Severity.CRITICAL)

    def record_connector_failure(self, service: str, message: str, status_code: int | None) -> None:
        if status_code in (401, 403):
            self.report(EventKind.PERMISSION_REVOKED, f"{service} refused the agent's credentials (HTTP {status_code})",
                        {"message": message[:300]}, severity=Severity.MEDIUM)
        now = time.monotonic()
        window = self.policy.circuit_breaker.window_minutes * 60
        self._failures = [t for t in self._failures if t > now - window] + [now]
        if len(self._failures) == self.policy.circuit_breaker.max_connector_failures:
            self.report(EventKind.CONNECTOR_FAILURES,
                        f"{len(self._failures)} connector failures in {self.policy.circuit_breaker.window_minutes} min",
                        {"last": message[:300]}, severity=Severity.HIGH)

    # ------------------------------------------------------------------ async side

    async def flush(self) -> None:
        """Deliver every queued event (audit log + admin alert)."""
        while True:
            try:
                event = self._queue.get_nowait()
            except queue.Empty:
                break
            await self._deliver(event)

    async def _deliver(self, event: SecurityEvent) -> None:
        self.events.append(event)
        del self.events[:-500]
        try:
            await self.audit.aappend("security_event", event.model_dump(mode="json"))
        except OSError as exc:
            log.critical("audit log write failed: %s", exc)
        key = f"{event.kind.value}:{event.summary}"
        now = time.monotonic()
        last = self._recent_alerts.get(key)
        if last is not None and now - last < self.policy.alert_dedupe_seconds and event.severity != Severity.CRITICAL:
            return
        self._recent_alerts[key] = now
        await self.alerter.send(event, self.kill_switch.state())

    def _watch_kill_switch(self) -> None:
        current = self.kill_switch.state()
        previous = self._last_kill
        self._last_kill = current
        if previous.engaged and not current.engaged:
            self._queue.put(SecurityEvent(
                kind=EventKind.KILL_SWITCH_CLEARED, severity=Severity.HIGH,
                summary="Kill switch was cleared; the agent is active again. If you did not do this, re-engage it "
                        "and investigate.", detail={"previous_reason": previous.reason}))
        elif current.engaged and (not previous.engaged or previous.level != current.level):
            if current.engaged_by == "safety-monitor":
                return  # the tripping event already alerted the admin with full context
            self._queue.put(SecurityEvent(
                kind=EventKind.KILL_SWITCH_ENGAGED, severity=Severity.CRITICAL,
                summary=f"Kill switch engaged (level={current.level.value if current.level else 'full'}): "
                        f"{current.reason}", detail={"engaged_by": current.engaged_by, "source": current.source}))

    def check_integrity(self) -> list[str]:
        if self.integrity is None:
            return []
        drift = self.integrity.drift()
        if drift:
            self.report(EventKind.SELF_MODIFICATION, f"{len(drift)} agent file(s) changed while running",
                        {"files": drift[:20]}, severity=Severity.CRITICAL)
        return drift

    async def tick(self) -> None:
        self._watch_kill_switch()
        await self.flush()

    async def run(self) -> None:
        interval = max(5, self.policy.integrity.check_interval_seconds)
        last_integrity = time.monotonic()
        while True:
            try:
                await self.tick()
                if time.monotonic() - last_integrity >= interval:
                    last_integrity = time.monotonic()
                    await asyncio.to_thread(self.check_integrity)
            except asyncio.CancelledError:
                raise
            except Exception:  # the monitor must keep running
                log.exception("safety monitor loop error")
            await asyncio.sleep(0.5)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run(), name="safety-monitor")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.tick()

    # ------------------------------------------------------------------ startup

    def startup_checks(self, state_path: str | Path, manifest_path: str | Path) -> None:
        """Restart-loop / self-heal detection and integrity verification at process start."""
        path = Path(state_path)
        state: dict[str, Any] = {}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                state = loaded if isinstance(loaded, dict) else {}
            except (OSError, ValueError):
                state = {}
        now = utcnow()
        window = timedelta(minutes=self.policy.restart_guard.window_minutes)
        starts = [s for s in (parse_dt(x) for x in state.get("starts", [])) if s and now - s <= window]
        starts.append(now)
        if state.get("running"):
            self.report(EventKind.UNCLEAN_RESTART, "previous agent process did not shut down cleanly",
                        {"previous_pid": state.get("pid")}, severity=Severity.MEDIUM)
        if len(starts) > self.policy.restart_guard.max_restarts:
            self.report(EventKind.RESTART_LOOP,
                        f"agent started {len(starts)} times in {self.policy.restart_guard.window_minutes} minutes",
                        {"starts": [iso(s) for s in starts]}, severity=Severity.CRITICAL)
        kill = self.kill_switch.state()
        if kill.engaged:
            self.report(EventKind.STARTED_WHILE_KILLED, f"agent started while kill switch engaged: {kill.reason}",
                        {"level": kill.level.value if kill.level else None}, severity=Severity.HIGH)
        self._write_state(path, {"starts": [iso(s) for s in starts], "running": True, "pid": os.getpid()})

        if self.integrity is not None:
            ok, problems = self.integrity.verify_manifest(manifest_path)
            live = not self.settings.mock_mode
            manifest_exists = Path(manifest_path).exists()
            if not ok and (manifest_exists or (live and self.policy.integrity.require_manifest_in_live_mode)):
                kind = EventKind.SELF_MODIFICATION if manifest_exists else EventKind.INTEGRITY_UNVERIFIED
                self.report(kind, "agent code/policy does not match the sealed integrity manifest",
                            {"problems": problems[:20]}, severity=Severity.CRITICAL)
        self._last_kill = self.kill_switch.state()

    def mark_clean_shutdown(self, state_path: str | Path) -> None:
        path = Path(state_path)
        try:
            state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except (OSError, ValueError):
            state = {}
        if not isinstance(state, dict):
            state = {}
        state["running"] = False
        self._write_state(path, state)

    @staticmethod
    def _write_state(path: Path, state: dict[str, Any]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError as exc:
            log.error("could not write safety state %s: %s", path, exc)
