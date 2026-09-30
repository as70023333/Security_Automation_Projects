"""Threat-intel fan-out and consensus scoring."""

from __future__ import annotations

import asyncio
import logging
import time

from .connectors.base import ConnectorError, IntelProvider
from .models import IntelSummary, IntelVerdict, ProviderResult
from .utils import dedupe

log = logging.getLogger("soc_agent.intel")


def aggregate(value: str, indicator_type: str, results: list[ProviderResult], min_sources: int) -> IntelSummary:
    responded = [r for r in results if not r.error]
    mal = [r for r in responded if r.verdict == IntelVerdict.MALICIOUS]
    sus = [r for r in responded if r.verdict == IntelVerdict.SUSPICIOUS]
    ben = [r for r in responded if r.verdict == IntelVerdict.BENIGN]
    strong = any(r.score >= 90 for r in mal)
    if len(mal) >= max(1, min_sources) or strong:
        verdict = IntelVerdict.MALICIOUS
    elif mal or sus:
        verdict = IntelVerdict.SUSPICIOUS
    elif ben:
        verdict = IntelVerdict.BENIGN
    else:
        verdict = IntelVerdict.UNKNOWN
    score = 0
    flagged = mal + sus
    if flagged:
        score = min(100, max(r.score for r in flagged) + 5 * max(0, len(mal) - 1))
    labels = dedupe([label for r in mal + sus + ben for label in r.labels if label])[:8]
    errors = [r for r in results if r.error]
    note = f"{len(errors)} provider(s) unavailable" if errors else ""
    return IntelSummary(
        indicator=value, indicator_type=indicator_type, verdict=verdict, score=score,
        malicious_sources=len(mal), suspicious_sources=len(sus), benign_sources=len(ben),
        providers_queried=len(results), providers_responded=len(responded), labels=labels, note=note,
        results=results,
    )


class IntelService:
    def __init__(self, providers: list[IntelProvider], *, min_sources: int, provider_timeout: float) -> None:
        self.providers = providers
        self.min_sources = min_sources
        self.provider_timeout = provider_timeout

    async def _one(self, provider: IntelProvider, value: str, indicator_type: str) -> ProviderResult:
        start = time.monotonic()
        try:
            result = await provider.lookup(value, indicator_type)
        except ConnectorError as exc:
            result = ProviderResult(provider=provider.name, indicator=value, indicator_type=indicator_type,
                                    error=str(exc))
        except Exception as exc:  # a broken feed must never break the investigation
            log.exception("intel provider %s crashed", provider.name)
            result = ProviderResult(provider=provider.name, indicator=value, indicator_type=indicator_type,
                                    error=f"unexpected error: {type(exc).__name__}")
        result.latency_ms = int((time.monotonic() - start) * 1000)
        return result

    async def enrich(self, value: str, indicator_type: str, timeout: float) -> IntelSummary:
        providers = [p for p in self.providers if p.supports(indicator_type, value)]
        if not providers:
            return IntelSummary(indicator=value, indicator_type=indicator_type, note="no intel providers configured")
        budget = min(timeout, self.provider_timeout)
        if budget <= 0.05:
            return IntelSummary(indicator=value, indicator_type=indicator_type, note="no time budget left for intel")
        tasks = {asyncio.create_task(self._one(p, value, indicator_type)): p for p in providers}
        done, pending = await asyncio.wait(tasks.keys(), timeout=budget)
        results = [t.result() for t in done]
        for task in pending:
            task.cancel()
            results.append(ProviderResult(provider=tasks[task].name, indicator=value, indicator_type=indicator_type,
                                          error=f"timed out after {budget:.1f}s", latency_ms=int(budget * 1000)))
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        order = {p.name: i for i, p in enumerate(providers)}
        results.sort(key=lambda r: order.get(r.provider, 99))
        return aggregate(value, indicator_type, results, self.min_sources)
