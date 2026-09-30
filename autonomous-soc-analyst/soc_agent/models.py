"""Core data models: alerts, entities, enrichment, actions and the case record."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .utils import normalize_hash, parse_ip


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------- enums


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def bump(self, levels: int = 1) -> "Severity":
        idx = max(0, min(len(_SEVERITY_ORDER) - 1, self.rank + levels))
        return _SEVERITY_ORDER[idx]

    @classmethod
    def highest(cls, *values: "Severity | None") -> "Severity":
        present = [v for v in values if v is not None]
        if not present:
            return cls.MEDIUM
        return max(present, key=lambda s: s.rank)

    @classmethod
    def parse(cls, value: Any, default: "Severity | None" = None) -> "Severity":
        """Map vendor severities (Defender, Sentinel, Splunk, QRadar 0-10, P1-P4...)."""
        fallback = default or cls.MEDIUM
        if value is None or isinstance(value, bool):
            return fallback
        if isinstance(value, Severity):
            return value
        if isinstance(value, (int, float)):
            return _severity_from_number(float(value))
        text = str(value).strip().lower()
        if not text:
            return fallback
        try:
            return _severity_from_number(float(text))
        except ValueError:
            return _SEVERITY_ALIASES.get(text, fallback)


_SEVERITY_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

_SEVERITY_ALIASES = {
    "info": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "severe": Severity.HIGH,
    "major": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "urgent": Severity.CRITICAL,
    "sev0": Severity.CRITICAL,
    "sev1": Severity.CRITICAL,
    "p1": Severity.CRITICAL,
    "sev2": Severity.HIGH,
    "p2": Severity.HIGH,
    "sev3": Severity.MEDIUM,
    "p3": Severity.MEDIUM,
    "sev4": Severity.LOW,
    "p4": Severity.LOW,
}


def _severity_from_number(value: float) -> Severity:
    """Numeric severities are interpreted on a 0-10 scale (QRadar magnitude style)."""
    if value >= 9:
        return Severity.CRITICAL
    if value >= 7:
        return Severity.HIGH
    if value >= 4:
        return Severity.MEDIUM
    if value >= 1:
        return Severity.LOW
    return Severity.INFORMATIONAL


class CaseStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    AWAITING_APPROVAL = "awaiting_approval"
    CLOSED = "closed"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNDETERMINED = "undetermined"


class Routing(str, Enum):
    PAGE = "page"  # immediate attention: infrastructure + security on-call
    QUEUE = "queue"  # handled "in the queue" during business hours
    AUTO_CLOSE = "auto_close"  # false positive, closed by the agent


class IntelVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ActionType(str, Enum):
    ISOLATE_DEVICE = "isolate_device"
    STOP_AND_QUARANTINE_FILE = "stop_and_quarantine_file"
    COLLECT_INVESTIGATION_PACKAGE = "collect_investigation_package"
    RUN_AV_SCAN = "run_av_scan"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    # reversals (rollback / auto-release)
    RELEASE_DEVICE = "release_device"
    UNBLOCK_IP = "unblock_ip"
    ENABLE_USER = "enable_user"


CONTAINMENT_ACTIONS = frozenset(
    {ActionType.ISOLATE_DEVICE, ActionType.BLOCK_IP, ActionType.DISABLE_USER}
)
REVERSAL_OF = {
    ActionType.ISOLATE_DEVICE: ActionType.RELEASE_DEVICE,
    ActionType.BLOCK_IP: ActionType.UNBLOCK_IP,
    ActionType.DISABLE_USER: ActionType.ENABLE_USER,
}
REVERSAL_ACTIONS = frozenset(REVERSAL_OF.values())


class ActionStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"  # not applicable (e.g. device not onboarded)
    BLOCKED = "blocked"  # denied by a guardrail / safety control
    AWAITING_APPROVAL = "awaiting_approval"
    DRY_RUN = "dry_run"
    TIMEOUT = "timeout"  # no confirmation inside the time budget: verify manually


EFFECTIVE_STATUSES = frozenset({ActionStatus.SUCCESS, ActionStatus.DRY_RUN})

# --------------------------------------------------------------------------- entities


class Device(BaseModel):
    hostname: str | None = None
    mde_id: str | None = None
    os: str | None = None
    ip: str | None = None

    @field_validator("hostname")
    @classmethod
    def _lower_host(cls, v: str | None) -> str | None:
        return v.strip().lower() if isinstance(v, str) and v.strip() else None

    @field_validator("mde_id")
    @classmethod
    def _lower_id(cls, v: str | None) -> str | None:
        return v.strip().lower() if isinstance(v, str) and v.strip() else None

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return parse_ip(v)

    @property
    def label(self) -> str:
        return self.hostname or self.mde_id or "unknown-device"


class User(BaseModel):
    upn: str | None = None
    sam_account: str | None = None
    domain: str | None = None
    object_id: str | None = None
    display_name: str | None = None

    @field_validator("upn", "sam_account", "domain", "object_id")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return v.strip().lower() if isinstance(v, str) and v.strip() else None

    @property
    def identifier(self) -> str | None:
        if self.upn:
            return self.upn
        if self.sam_account and self.domain:
            return f"{self.domain}\\{self.sam_account}"
        return self.sam_account or self.object_id

    def names(self) -> list[str]:
        """Every name this account is known by (used for policy/self-protection matching)."""
        out = [self.upn, self.sam_account, self.object_id]
        if self.upn and "@" in self.upn:
            out.append(self.upn.split("@", 1)[0])
        if self.sam_account and self.domain:
            out.append(f"{self.domain}\\{self.sam_account}")
        return [n for n in out if n]


class FileArtifact(BaseModel):
    name: str | None = None
    path: str | None = None
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None

    @field_validator("sha256", "sha1", "md5", mode="before")
    @classmethod
    def _hash(cls, v: Any, info: Any) -> str | None:
        normalized = normalize_hash(v)
        if normalized is None:
            return None
        algo, value = normalized
        return value if algo == info.field_name else None

    @property
    def best_hash(self) -> str | None:
        return self.sha256 or self.sha1 or self.md5

    def hashes(self) -> list[str]:
        return [h for h in (self.sha256, self.sha1, self.md5) if h]

    @property
    def label(self) -> str:
        return self.name or (self.best_hash or "unknown-file")[:16]


class Alert(BaseModel):
    id: str
    source: str
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: str | None = None
    detection_source: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    devices: list[Device] = Field(default_factory=list)
    users: list[User] = Field(default_factory=list)
    files: list[FileArtifact] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v: Any) -> Severity:
        return Severity.parse(v)

    @field_validator("ips", mode="before")
    @classmethod
    def _ips(cls, v: Any) -> list[str]:
        out: list[str] = []
        for item in v or []:
            ip = parse_ip(item)
            if ip and ip not in out:
                out.append(ip)
        return out

    @property
    def key(self) -> str:
        return f"{self.source}:{self.id}"


# --------------------------------------------------------------------------- enrichment


class ProviderResult(BaseModel):
    provider: str
    indicator: str
    indicator_type: str
    verdict: IntelVerdict = IntelVerdict.UNKNOWN
    score: int = 0
    found: bool = False
    labels: list[str] = Field(default_factory=list)
    detail: str = ""
    reference: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = 0
    error: str | None = None


class IntelSummary(BaseModel):
    indicator: str
    indicator_type: str
    verdict: IntelVerdict = IntelVerdict.UNKNOWN
    score: int = 0
    malicious_sources: int = 0
    suspicious_sources: int = 0
    benign_sources: int = 0
    providers_queried: int = 0
    providers_responded: int = 0
    labels: list[str] = Field(default_factory=list)
    note: str = ""
    results: list[ProviderResult] = Field(default_factory=list)


class UserActivity(BaseModel):
    timestamp: datetime | None = None
    kind: str = "sign_in"
    ip: str | None = None
    location: str | None = None
    country: str | None = None
    application: str | None = None
    success: bool | None = None
    risk: str | None = None
    detail: str = ""


class UserContext(BaseModel):
    user: User
    display_name: str | None = None
    enabled: bool | None = None
    job_title: str | None = None
    department: str | None = None
    on_prem_synced: bool | None = None
    privileged: bool = False
    roles: list[str] = Field(default_factory=list)
    activities: list[UserActivity] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    risk_score: int = 0
    source: str = ""
    errors: list[str] = Field(default_factory=list)


class NetworkConnection(BaseModel):
    remote_ip: str
    ports: list[int] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    from_suspect_process: bool = False


class NetworkSummary(BaseModel):
    device: str
    lookback_hours: int = 24
    connections: list[NetworkConnection] = Field(default_factory=list)
    c2_candidates: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- actions & case


class ActionRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act-"))
    action: ActionType
    target: str
    phase: str = "response"  # fast_path | response | approval | rollback | auto_release
    status: ActionStatus = ActionStatus.PENDING
    reason: str = ""
    detail: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    approved_by: str | None = None
    rolled_back: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None


class TimelineEvent(BaseModel):
    ts: datetime = Field(default_factory=utcnow)
    status: CaseStatus | None = None
    message: str


class Case(BaseModel):
    id: str = Field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:10].upper()}")
    alert: Alert
    alert_class: str = "unclassified"
    status: CaseStatus = CaseStatus.NEW
    verdict: Verdict = Verdict.UNDETERMINED
    severity: Severity = Severity.MEDIUM
    routing: Routing = Routing.QUEUE
    queue_priority: str = "P3"
    confidence: int = 0
    risk_score: int = 0
    reasons: list[str] = Field(default_factory=list)
    hash_intel: list[IntelSummary] = Field(default_factory=list)
    ip_intel: list[IntelSummary] = Field(default_factory=list)
    user_context: list[UserContext] = Field(default_factory=list)
    network: list[NetworkSummary] = Field(default_factory=list)
    actions: list[ActionRecord] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    summary: str = ""
    summary_source: str = "template"
    report_markdown: str = ""
    notifications: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    phase_timings: dict[str, float] = Field(default_factory=dict)
    dry_run: bool = False
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None
    elapsed_seconds: float | None = None
    sla_seconds: float = 28.0
    sla_met: bool | None = None

    def transition(self, status: CaseStatus, message: str) -> None:
        self.status = status
        self.timeline.append(TimelineEvent(status=status, message=message))

    def note(self, message: str) -> None:
        self.timeline.append(TimelineEvent(message=message))

    def find_action(self, action_id: str) -> ActionRecord | None:
        return next((a for a in self.actions if a.id == action_id), None)

    def hash_verdicts(self) -> dict[str, IntelSummary]:
        return {s.indicator: s for s in self.hash_intel}

    def ip_verdicts(self) -> dict[str, IntelSummary]:
        return {s.indicator: s for s in self.ip_intel}

    def context_for(self, user: User) -> UserContext | None:
        wanted = set(user.names())
        for ctx in self.user_context:
            if wanted & set(ctx.user.names()):
                return ctx
        return None
