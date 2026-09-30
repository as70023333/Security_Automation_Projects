"""IR policy: alert classification, response playbooks, guardrails and escalation rules.

The policy lives in YAML (``ir_policy.yaml``) so the security team can change how the
agent behaves without touching code. Every decision the agent takes can be traced
back to a rule in this file.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

from .models import ActionType, Alert, Severity, User


class ClassMatch(BaseModel):
    categories: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class AlertClassPolicy(BaseModel):
    name: str
    description: str = ""
    priority: int = 100
    match: ClassMatch = Field(default_factory=ClassMatch)
    base_severity: Severity = Severity.MEDIUM
    true_positive_min_severity: Severity | None = None
    immediate_actions: list[ActionType] = Field(default_factory=list)
    immediate_min_severity: Severity = Severity.INFORMATIONAL
    true_positive_actions: list[ActionType] = Field(default_factory=list)
    undetermined_actions: list[ActionType] = Field(default_factory=list)
    always_page: bool = False
    next_steps: list[str] = Field(default_factory=list)

    _keyword_res: list[re.Pattern[str]] = PrivateAttr(default_factory=list)

    @field_validator("base_severity", "immediate_min_severity", mode="before")
    @classmethod
    def _sev(cls, v: Any) -> Severity:
        return Severity.parse(v)

    @field_validator("true_positive_min_severity", mode="before")
    @classmethod
    def _opt_sev(cls, v: Any) -> Severity | None:
        return None if v is None else Severity.parse(v)

    def model_post_init(self, __context: Any) -> None:
        self._keyword_res = [
            re.compile(rf"(?<![a-z0-9]){re.escape(k.lower())}(?![a-z0-9])")
            for k in self.match.keywords
            if k.strip()
        ]

    def matches(self, alert: Alert) -> bool:
        category = _norm(alert.category or "")
        if category and any(_norm(c) == category for c in self.match.categories):
            return True
        text = f"{alert.title}\n{alert.description}".lower()
        if any(p.search(text) for p in self._keyword_res):
            return True
        for tech in alert.mitre_techniques:
            t = tech.strip().upper()
            for wanted in self.match.mitre_techniques:
                w = wanted.strip().upper()
                if t == w or t.startswith(w + "."):
                    return True
        return False


class Guardrails(BaseModel):
    protected_hosts: list[str] = Field(default_factory=list)
    protected_accounts: list[str] = Field(default_factory=list)
    privileged_accounts: list[str] = Field(default_factory=list)
    approval_required_actions: list[ActionType] = Field(default_factory=list)
    never_block_cidrs: list[str] = Field(default_factory=list)
    block_suspicious_ips: bool = False
    block_unknown_ips_contacted_by_malware: bool = True
    max_targets_per_action: int = 5
    max_actions_per_hour: dict[ActionType, int] = Field(default_factory=dict)
    auto_release_on_false_positive: bool = True
    allowlisted_hashes: list[str] = Field(default_factory=list)

    _host_res: list[re.Pattern[str]] = PrivateAttr(default_factory=list)
    _protected_res: list[re.Pattern[str]] = PrivateAttr(default_factory=list)
    _privileged_res: list[re.Pattern[str]] = PrivateAttr(default_factory=list)
    _never_block: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = PrivateAttr(
        default_factory=list
    )
    _allowlist: set[str] = PrivateAttr(default_factory=set)

    def model_post_init(self, __context: Any) -> None:
        self._host_res = [re.compile(p, re.IGNORECASE) for p in self.protected_hosts]
        self._protected_res = [re.compile(p, re.IGNORECASE) for p in self.protected_accounts]
        self._privileged_res = [re.compile(p, re.IGNORECASE) for p in self.privileged_accounts]
        self._never_block = [ipaddress.ip_network(c, strict=False) for c in self.never_block_cidrs]
        self._allowlist = {h.strip().lower() for h in self.allowlisted_hashes if h.strip()}


class Escalation(BaseModel):
    page_severities: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL])
    page_if_containment_incomplete: list[Severity] = Field(
        default_factory=lambda: [Severity.HIGH]
    )
    page_on_undetermined: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL])
    notify_false_positives: bool = False

    @field_validator(
        "page_severities", "page_if_containment_incomplete", "page_on_undetermined", mode="before"
    )
    @classmethod
    def _sevs(cls, v: Any) -> list[Severity]:
        return [Severity.parse(x) for x in (v or [])]


class TriagePolicy(BaseModel):
    min_malicious_sources: int = 2
    true_positive_score: int = 60


class IRPolicy(BaseModel):
    version: int = 1
    organization: str = "Organization"
    sla_seconds: float | None = None
    default_class: str = "suspicious_activity"
    triage: TriagePolicy = Field(default_factory=TriagePolicy)
    escalation: Escalation = Field(default_factory=Escalation)
    guardrails: Guardrails = Field(default_factory=Guardrails)
    alert_classes: list[AlertClassPolicy] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> "IRPolicy":
        names = [c.name for c in self.alert_classes]
        if len(names) != len(set(names)):
            raise ValueError("alert class names must be unique")
        if self.default_class not in names:
            raise ValueError(f"default_class '{self.default_class}' is not defined in alert_classes")
        self.alert_classes.sort(key=lambda c: c.priority)
        return self

    # ---- classification --------------------------------------------------------------

    def classify(self, alert: Alert) -> AlertClassPolicy:
        for cls in self.alert_classes:
            if cls.name != self.default_class and cls.matches(alert):
                return cls
        return self.get_class(self.default_class)

    def get_class(self, name: str) -> AlertClassPolicy:
        for cls in self.alert_classes:
            if cls.name == name:
                return cls
        raise KeyError(name)

    # ---- guardrail lookups -------------------------------------------------------------

    def is_protected_host(self, hostname: str | None) -> bool:
        if not hostname:
            return False
        short = hostname.split(".", 1)[0]
        return any(p.search(hostname) or p.search(short) for p in self.guardrails._host_res)

    def is_protected_account(self, user: User) -> bool:
        return _any_match(self.guardrails._protected_res, user.names())

    def is_privileged_account(self, user: User) -> bool:
        return _any_match(self.guardrails._privileged_res, user.names())

    def in_never_block(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in net for net in self.guardrails._never_block)

    def is_allowlisted_hash(self, value: str | None) -> bool:
        return value is not None and value.lower() in self.guardrails._allowlist

    def hourly_limit(self, action: ActionType) -> int | None:
        return self.guardrails.max_actions_per_hour.get(action)


def _norm(text: str) -> str:
    return re.sub(r"[\s_\-]", "", text).lower()


def _any_match(patterns: list[re.Pattern[str]], names: list[str]) -> bool:
    return any(p.search(n) for p in patterns for n in names)


def load_policy(path: str | Path) -> IRPolicy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: policy must be a YAML mapping")
    return IRPolicy.model_validate(data)
