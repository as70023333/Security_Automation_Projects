"""The safety gate: the last check immediately before ANY call that changes a system.

Checks, in order:
  1. Kill switch not engaged (re-read from disk on every call).
  2. Capability: the action type is granted in safety.yaml.
  3. Self-protection: the target is not the agent itself, its credentials or an admin.
  4. Scope / provenance: the target appears in the evidence of the case being worked.
     An action on anything else is treated as a breakout attempt.
  5. Circuit breaker: global containment rate across all cases.
Security denials are reported to the admin; the monitor decides whether to trip the
kill switch. Repeated denials trip it regardless.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..models import CONTAINMENT_ACTIONS, ActionRecord, ActionType, Case, Severity, User
from .events import EventKind, SafetyPolicy
from .killswitch import KillSwitch

if TYPE_CHECKING:
    from .monitor import SafetyMonitor

DEVICE_ACTIONS = frozenset(
    {
        ActionType.ISOLATE_DEVICE,
        ActionType.RELEASE_DEVICE,
        ActionType.COLLECT_INVESTIGATION_PACKAGE,
        ActionType.RUN_AV_SCAN,
        ActionType.STOP_AND_QUARANTINE_FILE,
    }
)
DESTRUCTIVE = CONTAINMENT_ACTIONS | {ActionType.STOP_AND_QUARANTINE_FILE}


@dataclass
class GateDecision:
    allowed: bool
    reason: str = ""
    kind: EventKind | None = None


class SafetyGate:
    def __init__(self, policy: SafetyPolicy, kill_switch: KillSwitch, monitor: "SafetyMonitor") -> None:
        self.policy = policy
        self.kill_switch = kill_switch
        self.monitor = monitor
        self._allowed = set(policy.allowed_actions)
        self._lock = threading.Lock()
        self._destructive: deque[float] = deque()
        self._denials: deque[float] = deque()
        self.stats = {"authorized": 0, "denied": 0}

    # ------------------------------------------------------------------ public

    def authorize(self, case: Case, record: ActionRecord) -> GateDecision:
        state = self.kill_switch.state()
        if state.engaged:
            return self._deny_quiet(f"kill switch engaged ({state.reason})")
        if record.action not in self._allowed:
            return self._deny(case, record, EventKind.CAPABILITY_VIOLATION,
                              f"action '{record.action.value}' is not granted by the safety policy")
        self_hit = self._self_target(record)
        if self_hit:
            return self._deny(case, record, EventKind.SELF_TARGETING, self_hit)
        scope_problem = self._out_of_scope(case, record)
        if scope_problem:
            return self._deny(case, record, EventKind.SCOPE_VIOLATION, scope_problem)
        if record.action in DESTRUCTIVE:
            with self._lock:
                window = self.policy.circuit_breaker.window_minutes * 60
                limit = self.policy.circuit_breaker.max_containment_actions
                self._prune(self._destructive, window)
                if len(self._destructive) >= limit:
                    tripped = True
                else:
                    tripped = False
                    self._destructive.append(time.monotonic())
            if tripped:
                self.monitor.report(
                    EventKind.CIRCUIT_BREAKER,
                    f"{limit} containment actions within {self.policy.circuit_breaker.window_minutes} minutes",
                    {"action": record.action.value, "target": record.target},
                    case_id=case.id, severity=Severity.CRITICAL,
                )
                self.stats["denied"] += 1
                return GateDecision(False, "circuit breaker open: containment rate limit reached", EventKind.CIRCUIT_BREAKER)
        self.stats["authorized"] += 1
        return GateDecision(True)

    # ------------------------------------------------------------------ checks

    def _self_target(self, record: ActionRecord) -> str | None:
        ids = self.policy.self_identities
        p = record.params
        if record.action in DEVICE_ACTIONS:
            host = str(p.get("hostname") or "").lower()
            short = host.split(".", 1)[0]
            if host and (host in ids.hostnames or short in ids.hostnames):
                return f"target host {host} is the agent's own infrastructure"
            if str(p.get("device_id") or "").lower() in ids.device_ids and p.get("device_id"):
                return "target device id belongs to the agent's own infrastructure"
        if record.action in (ActionType.BLOCK_IP, ActionType.UNBLOCK_IP):
            if str(p.get("ip") or "").lower() in ids.ips:
                return f"IP {p.get('ip')} belongs to the agent / its management plane"
        if record.action in (ActionType.DISABLE_USER, ActionType.ENABLE_USER):
            user = User.model_validate(p.get("user") or {})
            if set(user.names()) & set(ids.accounts):
                return f"account {user.identifier} is the agent's own identity or an admin account"
        return None

    def _out_of_scope(self, case: Case, record: ActionRecord) -> str | None:
        p = record.params
        alert = case.alert
        if record.action in DEVICE_ACTIONS:
            device_id = str(p.get("device_id") or "").lower()
            if device_id not in {d.mde_id for d in alert.devices if d.mde_id}:
                return f"device {device_id or '?'} is not part of case {case.id}"
            if record.action == ActionType.STOP_AND_QUARANTINE_FILE:
                sha1 = str(p.get("sha1") or "").lower()
                if sha1 not in {f.sha1 for f in alert.files if f.sha1}:
                    return f"file {sha1 or '?'} is not part of case {case.id}"
            return None
        if record.action in (ActionType.BLOCK_IP, ActionType.UNBLOCK_IP):
            ip = str(p.get("ip") or "")
            evidence = set(alert.ips)
            for net in case.network:
                evidence.update(c.remote_ip for c in net.connections)
            for ctx in case.user_context:
                evidence.update(a.ip for a in ctx.activities if a.ip)
            if ip not in evidence:
                return f"IP {ip or '?'} does not appear in the evidence of case {case.id}"
            return None
        if record.action in (ActionType.DISABLE_USER, ActionType.ENABLE_USER):
            user = User.model_validate(p.get("user") or {})
            names = set(user.names())
            if not names or not any(names & set(u.names()) for u in alert.users):
                return f"account {user.identifier or '?'} is not part of case {case.id}"
            return None
        return f"unrecognised action {record.action.value}"

    # ------------------------------------------------------------------ denial handling

    def _deny_quiet(self, reason: str) -> GateDecision:
        self.stats["denied"] += 1
        return GateDecision(False, reason)

    def _deny(self, case: Case, record: ActionRecord, kind: EventKind, reason: str) -> GateDecision:
        self.stats["denied"] += 1
        self.monitor.report(
            kind, reason,
            {"action": record.action.value, "target": record.target, "phase": record.phase, "action_id": record.id},
            case_id=case.id, severity=Severity.CRITICAL,
        )
        with self._lock:
            window = self.policy.circuit_breaker.window_minutes * 60
            self._prune(self._denials, window)
            self._denials.append(time.monotonic())
            repeated = len(self._denials) >= self.policy.circuit_breaker.max_denials
        if repeated:
            self.monitor.report(
                EventKind.REPEATED_DENIALS,
                f"{len(self._denials)} safety denials within {self.policy.circuit_breaker.window_minutes} minutes",
                {"last_reason": reason}, case_id=case.id, severity=Severity.CRITICAL, force_trip=True,
            )
        return GateDecision(False, reason, kind)

    @staticmethod
    def _prune(q: deque[float], window_seconds: float) -> None:
        cutoff = time.monotonic() - window_seconds
        while q and q[0] < cutoff:
            q.popleft()
