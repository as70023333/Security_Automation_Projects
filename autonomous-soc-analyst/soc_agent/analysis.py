"""Behavioural analysis of enrichment data (user sign-ins, network connections)."""

from __future__ import annotations

from datetime import timedelta

from .models import NetworkConnection, NetworkSummary, UserActivity, UserContext

COMMON_PORTS = frozenset({53, 80, 123, 443})
SENSITIVE_DIRECTORY_CHANGES = (
    "add member to role",
    "add app role assignment",
    "consent to application",
    "add service principal credentials",
    "update application",
    "user registered security info",
    "register security info",
    "reset password",
    "change user password",
    "set-inboxrule",
    "new-inboxrule",
    "update user",
)


def analyze_user_activity(ctx: UserContext) -> UserContext:
    """Populate ``ctx.flags`` and ``ctx.risk_score`` from the collected activity."""
    flags: list[str] = []
    score = 0
    sign_ins = sorted(
        (a for a in ctx.activities if a.kind == "sign_in" and a.timestamp is not None),
        key=lambda a: a.timestamp,  # type: ignore[arg-type,return-value]
    )
    successes = [a for a in sign_ins if a.success]
    failures = [a for a in sign_ins if a.success is False]

    travel = _impossible_travel(successes)
    if travel:
        flags.append(travel)
        score += 35
    else:
        countries = sorted({a.country for a in successes if a.country})
        if len(countries) >= 2:
            flags.append(f"Successful sign-ins from {len(countries)} countries ({', '.join(countries)})")
            score += 20

    if len(failures) >= 5:
        flags.append(f"{len(failures)} failed sign-ins (possible password spray / brute force)")
        score += 15
        last_failure = failures[-1].timestamp
        if last_failure and any(s.timestamp and s.timestamp > last_failure for s in successes):
            flags.append("Successful sign-in after repeated failures")
            score += 15

    risks = {(a.risk or "").lower() for a in sign_ins}
    if "high" in risks:
        flags.append("Entra ID rated a sign-in as HIGH risk")
        score += 25
    elif "medium" in risks:
        flags.append("Entra ID rated a sign-in as medium risk")
        score += 10

    for change in (a for a in ctx.activities if a.kind == "directory_change"):
        text = f"{change.detail} {change.application or ''}".lower()
        if any(k in text for k in SENSITIVE_DIRECTORY_CHANGES):
            flags.append(f"Sensitive directory change: {change.detail}")
            score += 15
            break

    if ctx.enabled is False:
        flags.append("Account is already disabled")

    ctx.flags = flags
    ctx.risk_score = min(100, score)
    return ctx


def flag_malicious_sign_in_ips(ctx: UserContext, malicious_ips: set[str]) -> None:
    hits = sorted({a.ip for a in ctx.activities if a.ip and a.ip in malicious_ips and a.success})
    if hits:
        ctx.flags.append(f"Successful sign-in from threat-intel flagged IP(s): {', '.join(hits)}")
        ctx.risk_score = min(100, ctx.risk_score + 30)


def _impossible_travel(successes: list[UserActivity]) -> str | None:
    for prev, cur in zip(successes, successes[1:], strict=False):
        if not (prev.country and cur.country and prev.timestamp and cur.timestamp):
            continue
        if prev.country == cur.country:
            continue
        gap = cur.timestamp - prev.timestamp
        if gap <= timedelta(hours=2):
            minutes = max(1, int(gap.total_seconds() // 60))
            return (
                f"Impossible travel: successful sign-ins from {prev.location or prev.country} "
                f"and {cur.location or cur.country} {minutes} minutes apart"
            )
    return None


def summarize_network(device: str, connections: list[NetworkConnection], lookback_hours: int) -> NetworkSummary:
    summary = NetworkSummary(device=device, lookback_hours=lookback_hours, connections=connections)
    summary.c2_candidates = [c.remote_ip for c in connections if c.from_suspect_process]
    total = sum(c.count for c in connections)
    summary.notes.append(
        f"{len(connections)} distinct public destinations, {total} connections in the last {lookback_hours}h"
    )
    if summary.c2_candidates:
        summary.notes.append(
            f"Suspect process contacted {len(summary.c2_candidates)} public IP(s): "
            + ", ".join(summary.c2_candidates[:10])
        )
    unusual = sorted({p for c in connections for p in c.ports if p not in COMMON_PORTS})
    if unusual:
        summary.notes.append("Uncommon remote ports: " + ", ".join(str(p) for p in unusual[:10]))
    return summary
