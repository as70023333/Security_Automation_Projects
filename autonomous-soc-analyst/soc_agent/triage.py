"""Deterministic, explainable triage: verdict, severity, confidence and routing.

No language model is involved in any decision here. Every point added or removed is
written to ``reasons`` so a human can audit exactly why the agent acted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    CONTAINMENT_ACTIONS,
    EFFECTIVE_STATUSES,
    ActionStatus,
    Case,
    IntelVerdict,
    Routing,
    Severity,
    Verdict,
)
from .policy import AlertClassPolicy, IRPolicy

SOURCE_POINTS = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 0,
    Severity.INFORMATIONAL: -10,
}
PRIORITY = {
    Severity.CRITICAL: "P1",
    Severity.HIGH: "P2",
    Severity.MEDIUM: "P3",
    Severity.LOW: "P4",
    Severity.INFORMATIONAL: "P4",
}
INCOMPLETE = frozenset({ActionStatus.FAILED, ActionStatus.TIMEOUT, ActionStatus.AWAITING_APPROVAL,
                        ActionStatus.BLOCKED})


@dataclass
class TriageResult:
    verdict: Verdict
    severity: Severity
    confidence: int
    risk_score: int
    reasons: list[str] = field(default_factory=list)


def _names(case: Case, verdict: IntelVerdict, kind: str) -> list[str]:
    files = {f.best_hash: f.label for f in case.alert.files if f.best_hash}
    intel = case.hash_intel if kind == "hash" else case.ip_intel
    out = []
    for s in intel:
        if s.verdict == verdict:
            name = files.get(s.indicator, s.indicator) if kind == "hash" else s.indicator
            srcs = f"{s.malicious_sources + s.suspicious_sources}/{s.providers_responded}"
            labels = f" [{', '.join(s.labels[:3])}]" if s.labels else ""
            out.append(f"{name} ({srcs} feeds{labels})")
    return out


def triage(case: Case, policy: IRPolicy, cls: AlertClassPolicy) -> TriageResult:
    reasons: list[str] = []
    score = 0
    alert = case.alert

    pts = SOURCE_POINTS[alert.severity]
    score += pts
    reasons.append(f"Source rated the alert {alert.severity.value} ({alert.detection_source or alert.source}) "
                   f"[{pts:+d}]")

    mal_files = _names(case, IntelVerdict.MALICIOUS, "hash")
    sus_files = _names(case, IntelVerdict.SUSPICIOUS, "hash")
    all_benign_files = bool(case.hash_intel) and all(s.verdict == IntelVerdict.BENIGN for s in case.hash_intel)
    if mal_files:
        score += 50
        reasons.append("Malicious file(s) confirmed by threat intel: " + "; ".join(mal_files) + " [+50]")
    elif sus_files:
        score += 20
        reasons.append("Suspicious file(s) per threat intel: " + "; ".join(sus_files) + " [+20]")
    if all_benign_files:
        score -= 40
        reasons.append("Every file hash in the alert is benign or allowlisted [-40]")

    mal_ips = [s.indicator for s in case.ip_intel if s.verdict == IntelVerdict.MALICIOUS]
    sus_ips = [s.indicator for s in case.ip_intel if s.verdict == IntelVerdict.SUSPICIOUS]
    if mal_ips:
        score += 30
        reasons.append("Malicious IP(s) involved: " + ", ".join(mal_ips) + " [+30]")
    elif sus_ips:
        score += 10
        reasons.append("Suspicious IP(s) involved: " + ", ".join(sus_ips) + " [+10]")

    user_risk = max((c.risk_score for c in case.user_context), default=0)
    if user_risk:
        pts = min(40, user_risk)
        score += pts
        flags = [f for c in case.user_context for f in c.flags]
        reasons.append("Account behaviour: " + "; ".join(flags[:4]) + f" [+{pts}]")

    suspect_dests = sorted({ip for n in case.network for ip in n.c2_candidates})
    if suspect_dests and mal_files:
        score += 10
        reasons.append(f"Malicious process communicated with {len(suspect_dests)} public IP(s) [+10]")

    score = max(0, min(100, score))
    strong = bool(mal_files or mal_ips)

    if strong or score >= policy.triage.true_positive_score:
        verdict = Verdict.TRUE_POSITIVE
        confidence = max(score, 80 if strong else 60)
    elif all_benign_files and not mal_ips and not sus_ips and user_risk < 20:
        verdict = Verdict.FALSE_POSITIVE
        confidence = max(70, 100 - score)
        reasons.append("No malicious indicators and all file evidence is benign → false positive")
    else:
        verdict = Verdict.UNDETERMINED
        confidence = 50
        reasons.append("Evidence is inconclusive → handed to a human with the evidence gathered")

    severity = Severity.highest(alert.severity, cls.base_severity)
    if verdict == Verdict.TRUE_POSITIVE:
        if cls.true_positive_min_severity:
            severity = Severity.highest(severity, cls.true_positive_min_severity)
        if strong:
            severity = Severity.highest(severity, Severity.HIGH)
        crown_jewels = [d.label for d in alert.devices if policy.is_protected_host(d.hostname)]
        privileged: list[str] = []
        for u in alert.users:
            ctx = case.context_for(u)
            if policy.is_privileged_account(u) or (ctx is not None and ctx.privileged):
                privileged.append(u.identifier or "unknown")
        if crown_jewels or privileged:
            severity = severity.bump()
            who = ", ".join([*crown_jewels, *privileged])
            reasons.append(f"Protected asset / privileged identity involved ({who}) → severity raised to "
                           f"{severity.value}")
    elif verdict == Verdict.FALSE_POSITIVE:
        severity = Severity.INFORMATIONAL

    return TriageResult(verdict=verdict, severity=severity, confidence=min(100, confidence), risk_score=score,
                        reasons=reasons)


def decide_routing(case: Case, policy: IRPolicy, cls: AlertClassPolicy, *, kill_switch_engaged: bool) -> Routing:
    esc = policy.escalation
    if case.verdict == Verdict.FALSE_POSITIVE:
        return Routing.AUTO_CLOSE
    if cls.always_page and case.verdict == Verdict.TRUE_POSITIVE:
        return Routing.PAGE
    if case.severity in esc.page_severities:
        return Routing.PAGE
    containment = [a for a in case.actions if a.action in CONTAINMENT_ACTIONS or a.status == ActionStatus.AWAITING_APPROVAL]
    incomplete = any(a.status in INCOMPLETE for a in containment)
    wanted_containment = any(a in CONTAINMENT_ACTIONS for a in cls.true_positive_actions)
    contained = any(a.action in CONTAINMENT_ACTIONS and a.status in EFFECTIVE_STATUSES and not a.rolled_back
                    for a in case.actions)
    if case.verdict == Verdict.TRUE_POSITIVE and wanted_containment and not contained:
        incomplete = True
    if case.verdict == Verdict.TRUE_POSITIVE and kill_switch_engaged:
        return Routing.PAGE  # the agent is not allowed to contain: a human must
    if case.severity in esc.page_if_containment_incomplete and incomplete:
        return Routing.PAGE
    if case.verdict == Verdict.UNDETERMINED and case.severity in esc.page_on_undetermined:
        return Routing.PAGE
    return Routing.QUEUE


def queue_priority(severity: Severity) -> str:
    return PRIORITY[severity]
