"""Incident report generation (Markdown) and the executive summary."""

from __future__ import annotations

import re
from typing import Any

from .models import (
    CONTAINMENT_ACTIONS,
    EFFECTIVE_STATUSES,
    ActionStatus,
    ActionType,
    Case,
    IntelVerdict,
    Routing,
    Verdict,
)
from .policy import AlertClassPolicy
from .utils import truncate

STATUS_MARK = {
    ActionStatus.SUCCESS: "✅ done",
    ActionStatus.DRY_RUN: "🧪 dry run",
    ActionStatus.FAILED: "❌ failed",
    ActionStatus.TIMEOUT: "⏱️ unconfirmed",
    ActionStatus.BLOCKED: "⛔ blocked",
    ActionStatus.AWAITING_APPROVAL: "✋ needs approval",
    ActionStatus.SKIPPED: "➖ skipped",
    ActionStatus.PENDING: "… pending",
}
ROUTING_TEXT = {
    Routing.PAGE: "PAGE: immediate attention (infrastructure + security on-call)",
    Routing.QUEUE: "QUEUE: handle during business hours",
    Routing.AUTO_CLOSE: "AUTO-CLOSED: false positive, no action needed",
}
VERB = {
    ActionType.ISOLATE_DEVICE: "isolated",
    ActionType.STOP_AND_QUARANTINE_FILE: "quarantined",
    ActionType.COLLECT_INVESTIGATION_PACKAGE: "collected forensics from",
    ActionType.RUN_AV_SCAN: "started AV scan on",
    ActionType.BLOCK_IP: "blocked",
    ActionType.DISABLE_USER: "disabled",
    ActionType.RELEASE_DEVICE: "released",
    ActionType.UNBLOCK_IP: "unblocked",
    ActionType.ENABLE_USER: "re-enabled",
}


_POINTS = re.compile(r"\s*\[[+-]\d+\]\s*$")


def plain_reason(reason: str) -> str:
    """Drop the trailing score marker (e.g. ' [+50]') from a triage reason."""
    return _POINTS.sub("", reason)


def _md(text: Any) -> str:
    """Escape table-breaking characters in untrusted values."""
    return truncate(str(text if text is not None else ""), 160).replace("|", "\\|").replace("\n", " ")


def template_summary(case: Case) -> str:
    a = case.alert
    hosts = ", ".join(d.label for d in a.devices) or "no device"
    users = ", ".join(u.identifier or "?" for u in a.users) or "no user"
    parts = [f"{case.severity.value.upper()} {case.alert_class.replace('_', ' ')} alert \"{truncate(a.title, 90)}\" "
             f"on {hosts} ({users})."]
    verdict = {
        Verdict.TRUE_POSITIVE: f"Verdict: TRUE POSITIVE ({case.confidence}% confidence)",
        Verdict.FALSE_POSITIVE: f"Verdict: FALSE POSITIVE ({case.confidence}% confidence)",
        Verdict.UNDETERMINED: "Verdict: UNDETERMINED - needs an analyst",
    }[case.verdict]
    top = next((r for r in case.reasons if "confirmed" in r or "Malicious" in r or "Account" in r), None)
    parts.append(f"{verdict}" + (f"; {truncate(plain_reason(top), 200)}." if top else "."))
    done = [a_ for a_ in case.actions if a_.status in EFFECTIVE_STATUSES and not a_.rolled_back
            and a_.phase != "auto_release" and a_.action in VERB]
    if done:
        grouped: dict[str, list[str]] = {}
        for act in done:
            grouped.setdefault(VERB[act.action], []).append(act.target)
        prefix = "Agent (dry run) would have " if case.dry_run else "Agent "
        parts.append(prefix + "; ".join(f"{v} {', '.join(t[:3])}" for v, t in grouped.items()) + ".")
    released = [act for act in case.actions if act.phase == "auto_release" and act.status in EFFECTIVE_STATUSES]
    if released:
        parts.append(f"Fast-path isolation of {', '.join(r.target for r in released)} was automatically released.")
    waiting = [act for act in case.actions if act.status == ActionStatus.AWAITING_APPROVAL]
    if waiting:
        parts.append(f"{len(waiting)} action(s) await your approval.")
    halted = [act for act in case.actions if act.status == ActionStatus.BLOCKED and "KILL SWITCH" in act.reason]
    if halted:
        parts.append(f"KILL SWITCH engaged: {len(halted)} action(s) were not executed and must be done manually.")
    failed = [act for act in case.actions if act.status in (ActionStatus.FAILED, ActionStatus.TIMEOUT)]
    if failed:
        parts.append(f"{len(failed)} action(s) failed or are unconfirmed - verify in the console.")
    parts.append(f"Routing: {case.routing.value.upper()}.")
    return " ".join(parts)


def llm_facts(case: Case) -> dict[str, Any]:
    return {
        "alert_title": case.alert.title,
        "alert_class": case.alert_class,
        "severity": case.severity.value,
        "verdict": case.verdict.value,
        "confidence": case.confidence,
        "routing": case.routing.value,
        "reasons": [plain_reason(r) for r in case.reasons],
        "devices": [d.label for d in case.alert.devices],
        "users": [u.identifier for u in case.alert.users],
        "file_intel": [{"file": s.indicator[:16], "verdict": s.verdict.value, "labels": s.labels[:3]}
                       for s in case.hash_intel],
        "ip_intel": [{"ip": s.indicator, "verdict": s.verdict.value} for s in case.ip_intel],
        "user_flags": [f for c in case.user_context for f in c.flags],
        "actions": [{"action": a.action.value, "target": a.target, "status": a.status.value}
                    for a in case.actions],
        "dry_run": case.dry_run,
    }


def build_report(case: Case, cls: AlertClassPolicy | None, report_url: str | None = None) -> str:
    a = case.alert
    lines: list[str] = []
    title_verdict = case.verdict.value.replace("_", " ").upper()
    lines.append(f"# SOC Agent Incident Report · {case.id}")
    lines.append("")
    if case.dry_run:
        lines.append("> 🧪 **DRY RUN / NOT ARMED** - no system was changed. Actions below show what the agent would do.")
        lines.append("")
    if any("KILL SWITCH" in x.reason for x in case.actions) or case.safety_notes:
        lines.append("> ⛔ **Safety controls intervened in this case** - see *Safety* below.")
        lines.append("")
    sla = "met" if case.sla_met else "MISSED"
    elapsed = f"{case.elapsed_seconds:.1f}s" if case.elapsed_seconds is not None else "n/a"
    lines += [
        f"**{title_verdict}** · **{case.severity.value.upper()}** · status **{case.status.value.upper()}** · "
        f"class **{case.alert_class}** · {case.queue_priority}",
        "",
        f"**Routing:** {ROUTING_TEXT[case.routing]}  ",
        f"**Alert:** {_md(a.title)} ({a.source}, id `{_md(a.id)}`)  ",
        f"**Detected:** {a.created_at:%Y-%m-%d %H:%M:%S} UTC · **Handled in:** {elapsed} (SLA {case.sla_seconds:.0f}s "
        f"{sla})",
        "",
        "## Summary",
        "",
        case.summary or template_summary(case),
        "",
    ]
    if report_url:
        lines += [f"[Open this case]({report_url})", ""]

    waiting = [x for x in case.actions if x.status == ActionStatus.AWAITING_APPROVAL]
    if waiting:
        lines += ["## Needs your decision", ""]
        for x in waiting:
            lines.append(f"- **{x.action.value}** → `{_md(x.target)}` - {_md(x.reason)}  ")
            lines.append(f"  approve: `POST /cases/{case.id}/actions/{x.id}/approve`")
        lines.append("")

    lines += ["## What the agent did", "", "| Phase | Action | Target | Result | Detail |", "|---|---|---|---|---|"]
    for x in case.actions:
        detail = x.detail or x.reason
        lines.append(f"| {x.phase} | {x.action.value} | {_md(x.target)} | {STATUS_MARK[x.status]} | {_md(detail)} |")
    if not case.actions:
        lines.append("| - | none | - | - | no response actions required by the IR policy |")
    lines.append("")

    lines += ["## Why (determination)", ""]
    lines += [f"- {_md(r)}" for r in case.reasons] or ["- no reasoning recorded"]
    lines.append("")

    lines += ["## Evidence", ""]
    if case.hash_intel:
        names = {f.best_hash: f for f in a.files}
        lines += ["**File hashes**", "", "| File | SHA256 / hash | Verdict | Feeds (mal/sus/responded) | Labels |",
                  "|---|---|---|---|---|"]
        for s in case.hash_intel:
            f = names.get(s.indicator)
            lines.append(f"| {_md(f.label if f else '?')} | `{s.indicator[:16]}…` | {s.verdict.value} "
                         f"({s.score}) | {s.malicious_sources}/{s.suspicious_sources}/{s.providers_responded} | "
                         f"{_md(', '.join(s.labels[:3]))} |")
        lines.append("")
        for s in case.hash_intel:
            hits = [r for r in s.results if r.verdict in (IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS)]
            if hits:
                lines.append(f"<details><summary>Feed detail for {s.indicator[:16]}…</summary>")
                lines.append("")
                for r in s.results:
                    lines.append(f"- {r.provider}: {r.error or f'{r.verdict.value} - {r.detail}'}")
                lines += ["", "</details>", ""]
    if case.ip_intel:
        lines += ["**IP addresses**", "", "| IP | Verdict | Feeds (mal/sus/responded) | Detail |", "|---|---|---|---|"]
        for s in case.ip_intel:
            top = next((r.detail for r in s.results if r.verdict == s.verdict and r.detail), s.note)
            lines.append(f"| {s.indicator} | {s.verdict.value} ({s.score}) | "
                         f"{s.malicious_sources}/{s.suspicious_sources}/{s.providers_responded} | {_md(top)} |")
        lines.append("")
    for ctx in case.user_context:
        who = ctx.display_name or ctx.user.identifier
        state = "enabled" if ctx.enabled else ("disabled" if ctx.enabled is False else "unknown")
        roles = f" · roles: {', '.join(ctx.roles)}" if ctx.roles else ""
        lines.append(f"**User {_md(who)}** ({_md(ctx.user.identifier)}) · {ctx.job_title or ''} · account {state}{roles}")
        lines.append("")
        for flag in ctx.flags or ["no anomalous activity found in the lookback window"]:
            lines.append(f"- {_md(flag)}")
        sign_ins = [x for x in ctx.activities if x.kind == "sign_in"]
        if sign_ins:
            ok = sum(1 for x in sign_ins if x.success)
            lines.append(f"- {len(sign_ins)} sign-ins reviewed ({ok} successful)")
        for err in ctx.errors:
            lines.append(f"- ⚠️ {_md(err)}")
        lines.append("")
    for net in case.network:
        lines += [f"**Network activity - {_md(net.device)}** (last {net.lookback_hours}h)", ""]
        lines += [f"- {_md(n)}" for n in net.notes]
        if net.connections:
            lines += ["", "| Remote IP | Ports | Process | Connections | Suspect process |", "|---|---|---|---|---|"]
            for c in net.connections[:10]:
                lines.append(f"| {c.remote_ip} | {', '.join(map(str, c.ports))} | {_md(', '.join(c.processes))} | "
                             f"{c.count} | {'yes' if c.from_suspect_process else ''} |")
        lines.append("")

    if cls and cls.next_steps and case.verdict != Verdict.FALSE_POSITIVE:
        lines += ["## Recommended next steps (IR playbook)", ""]
        lines += [f"{i}. {s}" for i, s in enumerate(cls.next_steps, 1)]
        lines.append("")

    active = [x for x in case.actions if x.action in CONTAINMENT_ACTIONS and x.status in EFFECTIVE_STATUSES
              and not x.rolled_back]
    if active:
        lines += ["## Rollback (active containment)", ""]
        for x in active:
            lines.append(f"- {x.action.value} `{_md(x.target)}` → `POST /cases/{case.id}/actions/{x.id}/rollback`")
        lines.append("")

    if case.safety_notes:
        lines += ["## Safety", ""]
        lines += [f"- {_md(n)}" for n in case.safety_notes]
        lines.append("")

    lines += ["## Timeline", ""]
    start = case.started_at
    for ev in case.timeline:
        offset = (ev.ts - start).total_seconds()
        state = f" **[{ev.status.value}]**" if ev.status else ""
        lines.append(f"- +{offset:5.2f}s{state} {_md(ev.message)}")
    lines.append("")
    if case.phase_timings:
        timings = " · ".join(f"{k} {v:.2f}s" for k, v in case.phase_timings.items())
        lines += [f"<sub>Phase timings: {timings}</sub>", ""]
    if case.errors:
        lines += ["## Pipeline notes", ""]
        lines += [f"- {_md(e)}" for e in case.errors]
        lines.append("")
    lines.append(f"<sub>Summary written by: {case.summary_source}. Decisions are rule-based (ir_policy.yaml); "
                 "no AI model makes containment decisions.</sub>")
    return "\n".join(lines)
