"""Defender XDR alert poller (alternative to webhooks): reads Graph security/alerts_v2."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from .connectors.base import ConnectorError
from .normalize import from_defender
from .utils import iso, parse_dt

if TYPE_CHECKING:
    from .connectors.microsoft import GraphAlertSource
    from .orchestrator import SOCAgent

log = logging.getLogger("soc_agent.poller")
WATERMARK_KEY = "defender_poller_watermark"


class DefenderPoller:
    def __init__(self, agent: "SOCAgent", source: "GraphAlertSource", interval_seconds: int) -> None:
        self.agent = agent
        self.source = source
        self.interval = max(10, interval_seconds)
        self._task: asyncio.Task[None] | None = None

    async def _watermark(self) -> datetime:
        stored = parse_dt(await self.agent.store.get_kv(WATERMARK_KEY))
        return stored or datetime.now(timezone.utc) - timedelta(minutes=10)

    async def poll_once(self) -> int:
        if self.agent.safety.kill_switch.state().halts_processing:
            return 0  # do not advance the watermark: alerts are picked up after resume
        since = await self._watermark()
        raw_alerts = await self.source.fetch_since(since)
        newest = since
        submitted = 0
        for raw in raw_alerts:
            status = str(raw.get("status") or "").lower()
            created = parse_dt(raw.get("createdDateTime"))
            if status in ("resolved", "inprogress"):
                newest = max(newest, created or newest)
                continue  # a human already owns it
            try:
                await self.agent.submit(from_defender(raw))
                submitted += 1
            except Exception as exc:
                log.error("could not submit Defender alert %s: %s", raw.get("id"), exc)
                break  # keep the watermark before this alert so it is retried
            newest = max(newest, created or newest)
        if newest > since:
            await self.agent.store.set_kv(WATERMARK_KEY, iso(newest))
        return submitted

    async def run(self) -> None:
        while True:
            try:
                n = await self.poll_once()
                if n:
                    log.info("poller submitted %d Defender alert(s)", n)
            except ConnectorError as exc:
                log.error("Defender poll failed: %s", exc)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Defender poller error")
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run(), name="defender-poller")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
