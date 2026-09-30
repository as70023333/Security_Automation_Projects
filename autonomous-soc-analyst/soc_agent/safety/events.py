"""Safety events and the safety policy (``safety.yaml``), owned by the platform admin."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import AwareDatetime, BaseModel, Field, field_validator

from ..models import ActionType, Severity, new_id, utcnow


class EventKind(str, Enum):
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"
    KILL_SWITCH_CLEARED = "kill_switch_cleared"
    EGRESS_VIOLATION = "egress_violation"  # tried to reach a host outside the allowlist
    SCOPE_VIOLATION = "scope_violation"  # action target not in the case evidence
    SELF_TARGETING = "self_targeting"  # action against the agent's own host/accounts/admins
    CAPABILITY_VIOLATION = "capability_violation"  # action type not permitted
    SELF_MODIFICATION = "self_modification"  # code/policy changed or write attempted
    SELF_HEAL_ATTEMPT = "self_heal_attempt"  # tried to clear/alter its own kill switch
    PROCESS_SPAWN_ATTEMPT = "process_spawn_attempt"  # tried to run a shell/process
    AUDIT_TAMPER_ATTEMPT = "audit_tamper_attempt"  # tried to truncate/delete the audit log
    RESTART_LOOP = "restart_loop"  # restarting repeatedly (self-healing behaviour)
    STARTED_WHILE_KILLED = "started_while_killed"
    UNCLEAN_RESTART = "unclean_restart"
    CIRCUIT_BREAKER = "circuit_breaker"  # too many containment actions in the window
    REPEATED_DENIALS = "repeated_denials"  # kept trying after safety denials
    PERMISSION_REVOKED = "permission_revoked"  # a system refused the agent's credentials
    CONNECTOR_FAILURES = "connector_failures"
    LLM_OUTPUT_ANOMALY = "llm_output_anomaly"
    INTEGRITY_UNVERIFIED = "integrity_unverified"
    ADMIN_ACTION = "admin_action"


# Human-readable meaning, shown in admin alerts.
EVENT_EXPLANATIONS: dict[EventKind, str] = {
    EventKind.EGRESS_VIOLATION: "The agent tried to contact a host that is not on its egress allowlist (possible "
    "exfiltration, SSRF or prompt injection).",
    EventKind.SCOPE_VIOLATION: "The agent tried to act on something that is not part of the incident it was "
    "working (breakout from case scope).",
    EventKind.SELF_TARGETING: "The agent tried to act on its own host, its own service accounts or an admin "
    "account it must never touch.",
    EventKind.CAPABILITY_VIOLATION: "The agent tried an action type that the safety policy does not grant it.",
    EventKind.SELF_MODIFICATION: "The agent's code or policy files changed, or the agent tried to write to them.",
    EventKind.SELF_HEAL_ATTEMPT: "The agent tried to remove, rename or overwrite its own kill switch.",
    EventKind.PROCESS_SPAWN_ATTEMPT: "The agent tried to launch a process or shell, which it never needs to do.",
    EventKind.AUDIT_TAMPER_ATTEMPT: "The agent tried to truncate, delete or rename its audit log.",
    EventKind.RESTART_LOOP: "The agent process restarted repeatedly in a short window (self-healing behaviour).",
    EventKind.STARTED_WHILE_KILLED: "The agent process started while the kill switch was engaged. It stays halted.",
    EventKind.UNCLEAN_RESTART: "The previous agent process did not shut down cleanly.",
    EventKind.CIRCUIT_BREAKER: "Too many containment actions in a short window. Automation halted to limit blast "
    "radius.",
    EventKind.REPEATED_DENIALS: "The agent kept attempting actions after the safety gate denied them.",
    EventKind.PERMISSION_REVOKED: "A target system refused the agent's credentials. The agent will not look for "
    "another way in.",
    EventKind.CONNECTOR_FAILURES: "Many connector calls are failing (possible credential revocation, outage or "
    "tampering).",
    EventKind.LLM_OUTPUT_ANOMALY: "The report-writing model produced suspicious output (possible prompt "
    "injection). The template summary was used instead.",
    EventKind.INTEGRITY_UNVERIFIED: "Code/policy integrity could not be verified against the sealed manifest.",
}


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("sev-"))
    ts: AwareDatetime = Field(default_factory=utcnow)
    kind: EventKind
    severity: Severity = Severity.HIGH
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)
    case_id: str | None = None
    tripped_kill_switch: bool = False


class SelfIdentities(BaseModel):
    """Things the agent must never act on: itself, its credentials and its overseers."""

    hostnames: list[str] = Field(default_factory=list)
    device_ids: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)

    @field_validator("hostnames", "device_ids", "accounts", "ips")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        return [x.strip().lower() for x in v if x and x.strip()]


class CircuitBreaker(BaseModel):
    window_minutes: int = 10
    max_containment_actions: int = 25
    max_denials: int = 3
    max_connector_failures: int = 20


class RestartGuard(BaseModel):
    window_minutes: int = 10
    max_restarts: int = 3


class IntegrityPolicy(BaseModel):
    check_interval_seconds: int = 30
    require_manifest_in_live_mode: bool = True


class RuntimeGuardPolicy(BaseModel):
    enabled: bool = True
    block_process_spawn: bool = True


class SafetyPolicy(BaseModel):
    allowed_actions: list[ActionType] = Field(default_factory=lambda: list(ActionType))
    self_identities: SelfIdentities = Field(default_factory=SelfIdentities)
    circuit_breaker: CircuitBreaker = Field(default_factory=CircuitBreaker)
    restart_guard: RestartGuard = Field(default_factory=RestartGuard)
    integrity: IntegrityPolicy = Field(default_factory=IntegrityPolicy)
    runtime_guard: RuntimeGuardPolicy = Field(default_factory=RuntimeGuardPolicy)
    trip_on: list[EventKind] = Field(
        default_factory=lambda: [
            EventKind.EGRESS_VIOLATION,
            EventKind.SCOPE_VIOLATION,
            EventKind.SELF_TARGETING,
            EventKind.CAPABILITY_VIOLATION,
            EventKind.SELF_MODIFICATION,
            EventKind.SELF_HEAL_ATTEMPT,
            EventKind.PROCESS_SPAWN_ATTEMPT,
            EventKind.AUDIT_TAMPER_ATTEMPT,
            EventKind.RESTART_LOOP,
            EventKind.CIRCUIT_BREAKER,
            EventKind.REPEATED_DENIALS,
            EventKind.INTEGRITY_UNVERIFIED,
        ]
    )
    full_stop_on: list[EventKind] = Field(
        default_factory=lambda: [
            EventKind.SELF_MODIFICATION,
            EventKind.SELF_HEAL_ATTEMPT,
            EventKind.PROCESS_SPAWN_ATTEMPT,
            EventKind.AUDIT_TAMPER_ATTEMPT,
        ]
    )
    alert_dedupe_seconds: int = 60


def load_safety_policy(path: str | Path) -> SafetyPolicy:
    p = Path(path)
    if not p.exists():
        return SafetyPolicy()
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: safety policy must be a YAML mapping")
    return SafetyPolicy.model_validate(data)
