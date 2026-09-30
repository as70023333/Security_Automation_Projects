"""SOC notifications: page the on-call or drop the case in the queue."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .config import Settings
from .connectors.http import request
from .models import ActionStatus, Case, Routing, Severity
from .report import STATUS_MARK
from .utils import truncate

log = logging.getLogger("soc_agent.notify")

PD_SEVERITY = {Severity.CRITICAL: "critical", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "info", Severity.INFORMATIONAL: "info"}


class Notifier:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None, *,
                 notify_false_positives: bool = False) -> None:
        self.settings = settings
        self.client = client
        self.notify_false_positives = notify_false_positives
        self.outbox: list[dict[str, Any]] = []  # what was sent (mock mode / tests / status)

    def report_url(self, case: Case) -> str | None:
        base = (self.settings.public_base_url or "").rstrip("/")
        return f"{base}/cases/{case.id}/report" if base.startswith("https://") else None

    def _headline(self, case: Case) -> str:
        icon = {Routing.PAGE: "🚨", Routing.QUEUE: "📥", Routing.AUTO_CLOSE: "✅"}[case.routing]
        return truncate(f"{icon} [{case.severity.value.upper()}] {case.verdict.value.replace('_', ' ').title()} · "
                        f"{case.alert_class} · {case.alert.title}", 150)

    def _action_lines(self, case: Case) -> list[str]:
        return [f"{STATUS_MARK[a.status]} {a.action.value} → {a.target}" for a in case.actions][:12]

    async def notify(self, case: Case, timeout: float) -> list[str]:
        if case.routing == Routing.AUTO_CLOSE and not self.notify_false_positives:
            return ["no notification (false positive auto-closed)"]
        jobs: list[tuple[str, Any]] = []
        if self.client is not None:
            if self.settings.teams_webhook_url:
                jobs.append(("teams", self._teams(case)))
            if self.settings.slack_webhook_url:
                jobs.append(("slack", self._slack(case)))
            if case.routing == Routing.PAGE and self.settings.secret("pagerduty_routing_key"):
                jobs.append(("pagerduty", self._pagerduty(case)))
            if self.settings.ticket_webhook_url:
                jobs.append(("ticket", self._ticket(case)))
        record = {"case_id": case.id, "routing": case.routing.value, "headline": self._headline(case),
                  "summary": case.summary, "actions": self._action_lines(case)}
        self.outbox.append(record)
        del self.outbox[:-200]
        if not jobs:
            log.info("NOTIFY %s %s", case.routing.value.upper(), record["headline"])
            return [f"{case.routing.value}: logged (no channels configured)"]
        budget = max(1.0, timeout)
        results = await asyncio.gather(*(asyncio.wait_for(coro, budget) for _, coro in jobs), return_exceptions=True)
        out = []
        for (name, _), result in zip(jobs, results, strict=True):
            if isinstance(result, BaseException):
                out.append(f"{name}: FAILED ({type(result).__name__}: {truncate(str(result), 120)})")
            else:
                out.append(f"{name}: sent")
        if case.routing == Routing.PAGE and not any(r.endswith(": sent") for r in out):
            log.critical("PAGE for %s could not be delivered on any channel: %s", case.id, out)
        return out

    async def _post(self, url: str, payload: dict[str, Any], service: str) -> None:
        assert self.client is not None
        await request(self.client, "POST", url, service=service, json_body=payload, retries=1,
                      expected=(200, 201, 202, 204))

    async def _teams(self, case: Case) -> None:
        facts = [{"title": "Verdict", "value": f"{case.verdict.value} ({case.confidence}%)"},
                 {"title": "Severity", "value": case.severity.value},
                 {"title": "Status", "value": case.status.value},
                 {"title": "Routing", "value": f"{case.routing.value} {case.queue_priority}"},
                 {"title": "Handled in", "value": f"{case.elapsed_seconds or 0:.1f}s"}]
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": self._headline(case), "weight": "Bolder", "size": "Medium", "wrap": True,
             "color": "Attention" if case.routing == Routing.PAGE else "Default"},
            {"type": "FactSet", "facts": facts},
            {"type": "TextBlock", "text": truncate(case.summary, 1500), "wrap": True},
            {"type": "TextBlock", "text": "\n".join(f"- {line}" for line in self._action_lines(case)) or "- none",
             "wrap": True, "fontType": "Monospace", "size": "Small"},
        ]
        card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                "type": "AdaptiveCard", "version": "1.4", "body": body}
        url = self.report_url(case)
        if url:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open report", "url": url}]
        await self._post(self.settings.teams_webhook_url or "", {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}, "Teams")

    async def _slack(self, case: Case) -> None:
        actions = "\n".join(self._action_lines(case)) or "none"
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": truncate(self._headline(case), 150)}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Verdict:* {case.verdict.value} ({case.confidence}%)"},
                {"type": "mrkdwn", "text": f"*Severity:* {case.severity.value}"},
                {"type": "mrkdwn", "text": f"*Status:* {case.status.value}"},
                {"type": "mrkdwn", "text": f"*Routing:* {case.routing.value} {case.queue_priority}"}]},
            {"type": "section", "text": {"type": "mrkdwn", "text": truncate(case.summary, 2900)}},
            {"type": "section", "text": {"type": "mrkdwn", "text": truncate(f"```{actions}```", 2900)}},
        ]
        url = self.report_url(case)
        if url:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"<{url}|Open report>"}})
        await self._post(self.settings.slack_webhook_url or "", {"text": self._headline(case), "blocks": blocks},
                         "Slack")

    async def _pagerduty(self, case: Case) -> None:
        await self._post("https://events.pagerduty.com/v2/enqueue", {
            "routing_key": self.settings.secret("pagerduty_routing_key"),
            "event_action": "trigger",
            "dedup_key": f"soc-agent-{case.id}",
            "payload": {"summary": truncate(self._headline(case), 1000), "source": "soc-agent",
                        "severity": PD_SEVERITY[case.severity], "component": case.alert_class,
                        "custom_details": {"summary": case.summary, "actions": self._action_lines(case),
                                           "report": self.report_url(case)}},
        }, "PagerDuty")

    async def _ticket(self, case: Case) -> None:
        await self._post(self.settings.ticket_webhook_url or "", {
            "case_id": case.id, "title": case.alert.title, "priority": case.queue_priority,
            "severity": case.severity.value, "verdict": case.verdict.value, "status": case.status.value,
            "routing": case.routing.value, "alert_class": case.alert_class, "summary": case.summary,
            "report_markdown": case.report_markdown, "report_url": self.report_url(case),
            "awaiting_approval": [a.id for a in case.actions if a.status == ActionStatus.AWAITING_APPROVAL],
        }, "ticket webhook")
