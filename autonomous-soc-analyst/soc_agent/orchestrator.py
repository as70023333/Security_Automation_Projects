"""The Autonomous SOC Analyst pipeline.

  alert ─► classify ─► resolve devices ─┬─► fast-path containment (ransomware etc.) ──┐
                                        └─► enrichment in parallel:                    │
                                             hash intel (all feeds) · user activity   │
                                             network traffic ─► C2 IP intel           │
          triage (rules) ◄─────────────────────────────────────────────────────────────┘
             ─► response actions (IR policy + guardrails + safety gate)
             ─► auto-release on false positive ─► status / routing
             ─► report ─► page or queue ─► persist + audit

Everything runs against a single deadline (default 28s). Each phase gets a slice of the
remaining budget while reserving time for the phases after it, so a slow feed can never
prevent containment, the report, or the notification.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Awaitable, Iterator

from .actions import ActionExecutor, ActionPlanner
from .analysis import analyze_user_activity, flag_malicious_sign_in_ips
from .config import Settings
from .connectors import Connectors, build_connectors
from .connectors.base import ConnectorError
from .connectors.llm import screen_summary
from .intel import IntelService
from .models import (
    CONTAINMENT_ACTIONS,
    EFFECTIVE_STATUSES,
    ActionStatus,
    ActionType,
    Alert,
    Case,
    CaseStatus,
    Device,
    FileArtifact,
    IntelSummary,
    IntelVerdict,
    Routing,
    Severity,
    User,
    UserContext,
    Verdict,
    utcnow,
)
from .notify import Notifier
from .policy import AlertClassPolicy, IRPolicy, load_policy
from .report import build_report, llm_facts, template_summary
from .safety import EventKind, SafetySystem, build_safety
from .store import CaseStore
from .triage import decide_routing, queue_priority, triage
from .utils import Deadline, is_public_ip, normalize_hash

log = logging.getLogger("soc_agent")


class AgentHalted(RuntimeError):
    """Raised when the kill switch is at FULL stop: no alert processing at all."""


def compute_status(case: Case) -> CaseStatus:
    active = [a for a in case.actions
              if a.action in CONTAINMENT_ACTIONS and a.status in EFFECTIVE_STATUSES and not a.rolled_back]
    if case.verdict == Verdict.FALSE_POSITIVE:
        return CaseStatus.CLOSED if not active else CaseStatus.INVESTIGATING
    if any(a.status == ActionStatus.AWAITING_APPROVAL for a in case.actions):
        return CaseStatus.AWAITING_APPROVAL
    if any(a.action == ActionType.STOP_AND_QUARANTINE_FILE and a.status in EFFECTIVE_STATUSES for a in case.actions):
        return CaseStatus.REMEDIATED
    if active:
        return CaseStatus.CONTAINED
    return CaseStatus.INVESTIGATING


def _status_message(case: Case) -> str:
    active = [f"{a.action.value} {a.target}" for a in case.actions
              if a.action in CONTAINMENT_ACTIONS and a.status in EFFECTIVE_STATUSES and not a.rolled_back]
    waiting = [f"{a.action.value} {a.target}" for a in case.actions if a.status == ActionStatus.AWAITING_APPROVAL]
    parts = []
    if active:
        parts.append("containment in effect: " + "; ".join(active))
    if waiting:
        parts.append("awaiting approval: " + "; ".join(waiting))
    if case.verdict == Verdict.FALSE_POSITIVE:
        parts.append("false positive")
    return ", ".join(parts) or "no containment applied; handed to analyst queue"


class SOCAgent:
    def __init__(self, settings: Settings, policy: IRPolicy, connectors: Connectors, store: CaseStore,
                 safety: SafetySystem) -> None:
        self.settings = settings
        self.policy = policy
        self.connectors = connectors
        self.store = store
        self.safety = safety
        self.sla = float(policy.sla_seconds or settings.sla_seconds)
        self.planner = ActionPlanner(policy, allow_documentation_ips=settings.mock_mode)
        self.executor = ActionExecutor(settings, policy, connectors, store, safety)
        self.intel = IntelService(connectors.intel, min_sources=policy.triage.min_malicious_sources,
                                  provider_timeout=settings.intel_provider_timeout)
        self.notifier = Notifier(settings, connectors.notify_client,
                                 notify_false_positives=policy.escalation.notify_false_positives)
        self.reports_dir = Path(settings.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._queue: asyncio.Queue[Alert] | None = None
        self._workers: list[asyncio.Task[None]] = []
        self._case_locks: dict[str, asyncio.Lock] = {}

    # ================================================================== lifecycle

    async def start(self) -> None:
        self._queue = asyncio.Queue(maxsize=1000)
        self._workers = [asyncio.create_task(self._worker(i), name=f"soc-worker-{i}")
                         for i in range(self.settings.worker_count)]

    async def stop(self) -> None:
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []

    async def aclose(self) -> None:
        await self.stop()
        await self.safety.aclose()
        self.store.close()

    async def submit(self, alert: Alert) -> None:
        kill = self.safety.kill_switch.state()
        if kill.halts_processing:
            raise AgentHalted(kill.reason)
        if self._queue is None:
            raise RuntimeError("agent workers are not running")
        self._queue.put_nowait(alert)

    async def drain(self) -> None:
        if self._queue is not None:
            await self._queue.join()

    async def _worker(self, idx: int) -> None:
        assert self._queue is not None
        while True:
            alert = await self._queue.get()
            try:
                await self.handle_alert(alert)
            except AgentHalted as exc:
                await self.store.set_kv(f"held:{alert.key}", alert.model_dump_json())
                log.warning("alert %s held (kill switch): %s", alert.key, exc)
            except Exception:
                log.exception("worker %d failed on alert %s", idx, alert.key)
            finally:
                self._queue.task_done()

    # ================================================================== pipeline

    async def handle_alert(self, alert: Alert) -> Case:
        kill = self.safety.kill_switch.state()
        if kill.halts_processing:
            raise AgentHalted(kill.reason)
        deadline = Deadline(self.sla)
        case = Case(alert=alert, sla_seconds=self.sla, dry_run=self.settings.effective_dry_run)
        existing = await self.store.claim_alert(alert.key, case.id)
        if existing:
            stored = await self.store.get_case(existing)
            if stored is not None:
                log.info("duplicate alert %s -> %s", alert.key, existing)
                return stored
            case.id = existing  # claimed earlier but never saved (crash): reprocess under the same id
        await self.safety.audit.aappend("case_opened", {"case_id": case.id, "alert": alert.key, "title": alert.title,
                                                        "source": alert.source, "dry_run": case.dry_run})
        cls: AlertClassPolicy | None = None
        try:
            cls = await self._pipeline(case, deadline)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("pipeline failure for %s", case.id)
            case.errors.append(f"pipeline error: {type(exc).__name__}: {exc}")
            case.note("Pipeline error: escalating to a human")
            case.routing = Routing.PAGE
            case.status = compute_status(case)
        await self._finish(case, deadline, cls)
        return case

    @contextmanager
    def _phase(self, case: Case, name: str) -> Iterator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            case.phase_timings[name] = round(time.monotonic() - start, 3)

    async def _pipeline(self, case: Case, deadline: Deadline) -> AlertClassPolicy:
        alert = case.alert
        sla = self.sla
        case.transition(CaseStatus.INVESTIGATING, f"Alert received from {alert.source}: {alert.title}")
        cls = self.policy.classify(alert)
        case.alert_class = cls.name
        case.severity = Severity.highest(alert.severity, cls.base_severity)
        case.note(f"Classified as '{cls.name}' by IR policy; preliminary severity {case.severity.value}")

        with self._phase(case, "resolve_devices"):
            await self._resolve_devices(case, timeout=deadline.budget(reserve=0.75 * sla, cap=0.15 * sla))

        fast_task: asyncio.Task[None] | None = None
        if cls.immediate_actions and alert.severity.rank >= cls.immediate_min_severity.rank:
            planned = self.planner.plan(case, cls.immediate_actions, "fast_path")
            if planned:
                case.note("Fast-path containment started per IR policy: "
                          + ", ".join(f"{p.action.value} {p.target}" for p in planned))
                fast_task = asyncio.create_task(
                    self.executor.execute(case, planned, timeout=deadline.budget(reserve=0.45 * sla, cap=0.35 * sla)))

        with self._phase(case, "enrichment"):
            await self._enrich(case, deadline)

        with self._phase(case, "triage"):
            result = triage(case, self.policy, cls)
            case.verdict, case.severity = result.verdict, result.severity
            case.confidence, case.risk_score, case.reasons = result.confidence, result.risk_score, result.reasons
            case.note(f"Determination: {case.verdict.value} ({case.confidence}% confidence), severity "
                      f"{case.severity.value}, risk score {case.risk_score}")

        if fast_task is not None:
            with self._phase(case, "fast_path_wait"):
                await fast_task

        with self._phase(case, "response"):
            if case.verdict == Verdict.TRUE_POSITIVE:
                wanted = cls.true_positive_actions
            elif case.verdict == Verdict.UNDETERMINED:
                wanted = cls.undetermined_actions
            else:
                wanted = []
            planned = self.planner.plan(case, wanted, "response")
            if planned:
                await self.executor.execute(case, planned,
                                            timeout=deadline.budget(reserve=0.18 * sla, cap=0.35 * sla))
            if case.verdict == Verdict.FALSE_POSITIVE and self.policy.guardrails.auto_release_on_false_positive:
                for act in list(case.actions):
                    if (act.action == ActionType.ISOLATE_DEVICE and act.phase == "fast_path"
                            and act.status in EFFECTIVE_STATUSES and not act.rolled_back):
                        rb = await self.executor.rollback(
                            case, act.id, "agent (false-positive determination)", phase="auto_release",
                            timeout=deadline.budget(reserve=0.12 * sla, cap=0.2 * sla))
                        case.note(f"Auto-release of {act.target}: {rb.status.value}")

        case.transition(compute_status(case), _status_message(case))
        case.routing = decide_routing(case, self.policy, cls,
                                      kill_switch_engaged=self.safety.kill_switch.engaged)
        case.queue_priority = queue_priority(case.severity)
        return cls

    # ------------------------------------------------------------------ device resolution

    async def _resolve_devices(self, case: Case, timeout: float) -> None:
        edr = self.connectors.edr
        todo = [d for d in case.alert.devices if not d.mde_id and d.hostname]
        if edr is None or not todo or timeout <= 0:
            return

        async def one(dev_hostname: str) -> None:
            found = await edr.resolve_device(dev_hostname)
            for d in case.alert.devices:
                if d.hostname == dev_hostname and found is not None:
                    d.mde_id = found.mde_id
                    d.os = d.os or found.os
                    d.ip = d.ip or found.ip

        await self._bounded(case, {f"resolve {d.hostname}": one(d.hostname or "") for d in todo[:5]}, timeout)

    # ------------------------------------------------------------------ enrichment

    async def _enrich(self, case: Case, deadline: Deadline) -> None:
        sla = self.sla
        budget = deadline.budget(reserve=0.40 * sla, cap=0.55 * sla)
        end = time.monotonic() + budget
        alert = case.alert
        jobs: dict[str, Awaitable[None]] = {}
        enriched_ips: set[str] = set()

        seen_hashes: set[str] = set()
        for f in alert.files:
            h = f.best_hash
            if not h or h in seen_hashes or len(seen_hashes) >= 5:
                continue
            seen_hashes.add(h)
            if any(self.policy.is_allowlisted_hash(x) for x in f.hashes()):
                case.hash_intel.append(IntelSummary(indicator=h, indicator_type="hash", verdict=IntelVerdict.BENIGN,
                                                    labels=["allowlisted"], note="allowlisted by IR policy"))
                continue
            jobs[f"hash intel {f.label}"] = self._hash_intel(case, f, end)
        for ip in alert.ips:
            if len(enriched_ips) >= 5:
                break
            if is_public_ip(ip, allow_documentation=self.settings.mock_mode):
                enriched_ips.add(ip)
                jobs[f"IP intel {ip}"] = self._ip_intel(case, ip, end)
        if self.connectors.identity is not None:
            for u in alert.users[:3]:
                jobs[f"user activity {u.identifier}"] = self._user_context(case, u)
        if self.connectors.edr is not None:
            for d in [d for d in alert.devices if d.mde_id or d.hostname][:3]:
                jobs[f"network activity {d.label}"] = self._network(case, d, end, enriched_ips)
        if not jobs:
            case.note("No enrichable entities in the alert")
            return
        case.note(f"Enrichment started: {len(jobs)} parallel lookups ({len(self.connectors.intel)} intel feeds)")
        await self._bounded(case, jobs, budget)
        malicious_ips = {s.indicator for s in case.ip_intel if s.verdict == IntelVerdict.MALICIOUS}
        for ctx in case.user_context:
            flag_malicious_sign_in_ips(ctx, malicious_ips)
        case.note(f"Enrichment complete: {len(case.hash_intel)} hash(es), {len(case.ip_intel)} IP(s), "
                  f"{len(case.user_context)} account(s), {len(case.network)} network profile(s)")

    async def _bounded(self, case: Case, jobs: dict[str, Awaitable[None]], timeout: float) -> None:
        async def guarded(name: str, job: Awaitable[None]) -> None:
            try:
                await job
            except ConnectorError as exc:
                case.errors.append(f"{name}: {exc}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("%s failed", name)
                case.errors.append(f"{name}: unexpected {type(exc).__name__}")

        tasks = {asyncio.create_task(guarded(n, j)): n for n, j in jobs.items()}
        if timeout <= 0:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            case.errors.append("no time budget left for: " + ", ".join(tasks.values()))
            return
        _done, pending = await asyncio.wait(tasks.keys(), timeout=timeout)
        for t in pending:
            t.cancel()
            case.errors.append(f"{tasks[t]}: timed out after {timeout:.1f}s (partial evidence used)")
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _hash_intel(self, case: Case, f: FileArtifact, end: float) -> None:
        h = f.best_hash or ""
        summary = await self.intel.enrich(h, "hash", timeout=end - time.monotonic())
        case.hash_intel.append(summary)
        for r in summary.results:  # back-fill SHA1 (Defender quarantine needs it) and other hashes
            for algo in ("sha1", "sha256", "md5"):
                value = r.attributes.get(algo)
                norm = normalize_hash(value)
                if norm and norm[0] == algo and not getattr(f, algo):
                    setattr(f, algo, norm[1])

    async def _ip_intel(self, case: Case, ip: str, end: float) -> None:
        case.ip_intel.append(await self.intel.enrich(ip, "ip", timeout=end - time.monotonic()))

    async def _user_context(self, case: Case, user: User) -> None:
        identity = self.connectors.identity
        assert identity is not None
        try:
            ctx = await identity.get_user_context(user, self.settings.user_activity_lookback_hours)
        except ConnectorError as exc:
            case.user_context.append(UserContext(user=user, errors=[str(exc)], source=identity.name))
            raise
        analyze_user_activity(ctx)
        case.user_context.append(ctx)
        # Carry resolved identifiers back to the alert entity (used for approvals / scope checks).
        for u in case.alert.users:
            if set(u.names()) & set(user.names()):
                u.upn = u.upn or ctx.user.upn
                u.object_id = u.object_id or ctx.user.object_id

    async def _network(self, case: Case, device: Device, end: float, enriched_ips: set[str]) -> None:
        edr = self.connectors.edr
        assert edr is not None
        suspects = [h for f in case.alert.files for h in f.hashes()]
        summary = await edr.network_activity(device, suspects, self.settings.network_lookback_hours)
        case.network.append(summary)
        new_ips: list[str] = []
        for ip in summary.c2_candidates:
            if ip in enriched_ips or len(new_ips) >= 5:
                continue
            if is_public_ip(ip, allow_documentation=self.settings.mock_mode):
                enriched_ips.add(ip)
                new_ips.append(ip)
        if new_ips:
            results = await asyncio.gather(*(self.intel.enrich(ip, "ip", timeout=end - time.monotonic())
                                             for ip in new_ips))
            case.ip_intel.extend(results)

    # ------------------------------------------------------------------ report + notify

    async def _finish(self, case: Case, deadline: Deadline, cls: AlertClassPolicy | None) -> None:
        with self._phase(case, "report"):
            case.summary = template_summary(case)
            case.summary_source = "rule-based template"
            summarizer = self.connectors.summarizer
            if summarizer is not None and case.verdict != Verdict.FALSE_POSITIVE:
                budget = min(self.settings.llm_timeout_seconds, deadline.remaining() - 0.1 * self.sla)
                if budget >= 1.0:
                    try:
                        text = await asyncio.wait_for(summarizer.summarize(llm_facts(case), budget), budget + 0.5)
                        problem = screen_summary(text)
                        if problem:
                            self.safety.monitor.report(EventKind.LLM_OUTPUT_ANOMALY,
                                                       f"report summary rejected: {problem}",
                                                       {"excerpt": text[:300]}, case_id=case.id,
                                                       severity=Severity.MEDIUM)
                            case.errors.append("AI summary rejected by output guard; template used")
                        else:
                            case.summary, case.summary_source = text, summarizer.name
                    except (ConnectorError, asyncio.TimeoutError) as exc:
                        case.errors.append(f"AI summary unavailable ({type(exc).__name__}); template used")
            case.elapsed_seconds = round(deadline.elapsed(), 2)
            case.report_markdown = build_report(case, cls, self.notifier.report_url(case))
        with self._phase(case, "notify"):
            case.notifications = await self.notifier.notify(case, timeout=max(2.0, deadline.remaining()))
        case.completed_at = utcnow()
        case.elapsed_seconds = round(deadline.elapsed(), 2)
        case.sla_met = case.elapsed_seconds <= self.sla
        case.note(f"Report delivered ({case.routing.value}) in {case.elapsed_seconds:.2f}s: "
                  + "; ".join(case.notifications))
        case.report_markdown = build_report(case, cls, self.notifier.report_url(case))
        await self.store.save_case(case)
        await self._write_report_files(case)
        await self.safety.audit.aappend("case_completed", {
            "case_id": case.id, "verdict": case.verdict.value, "severity": case.severity.value,
            "status": case.status.value, "routing": case.routing.value, "elapsed": case.elapsed_seconds,
            "sla_met": case.sla_met, "actions": [f"{a.action.value}:{a.target}:{a.status.value}" for a in case.actions],
        })
        await self.safety.monitor.flush()
        log.info("%s %s %s %s %s in %.2fs", case.id, case.verdict.value, case.severity.value, case.status.value,
                 case.routing.value, case.elapsed_seconds)

    async def _write_report_files(self, case: Case) -> None:
        def write() -> None:
            (self.reports_dir / f"{case.id}.md").write_text(case.report_markdown, encoding="utf-8")
            (self.reports_dir / f"{case.id}.json").write_text(case.model_dump_json(indent=2), encoding="utf-8")

        try:
            await asyncio.to_thread(write)
        except OSError as exc:
            case.errors.append(f"could not write report files: {exc}")

    # ================================================================== human-in-the-loop

    def _lock(self, case_id: str) -> asyncio.Lock:
        return self._case_locks.setdefault(case_id, asyncio.Lock())

    async def _load(self, case_id: str) -> Case:
        case = await self.store.get_case(case_id)
        if case is None:
            raise LookupError(f"case {case_id} not found")
        return case

    async def _refresh(self, case: Case, message: str) -> None:
        cls = None
        try:
            cls = self.policy.get_class(case.alert_class)
        except KeyError:
            pass
        case.transition(compute_status(case), message)
        if case.summary_source == "rule-based template":
            case.summary = template_summary(case)
        case.report_markdown = build_report(case, cls, self.notifier.report_url(case))
        await self.store.save_case(case)
        await self._write_report_files(case)
        await self.safety.monitor.flush()

    async def approve_action(self, case_id: str, action_id: str, approver: str) -> Case:
        async with self._lock(case_id):
            case = await self._load(case_id)
            rec = await self.executor.approve(case, action_id, approver)
            await self._refresh(case, f"{rec.action.value} {rec.target} approved by {approver}: {rec.status.value}")
            return case

    async def rollback_action(self, case_id: str, action_id: str, requested_by: str) -> Case:
        async with self._lock(case_id):
            case = await self._load(case_id)
            rec = await self.executor.rollback(case, action_id, requested_by)
            await self._refresh(case, f"{rec.action.value} {rec.target} by {requested_by}: {rec.status.value}")
            return case

    async def replay_held(self) -> int:
        """Re-submit alerts held while the kill switch was at FULL stop."""
        count = 0
        for key, value in await self.store.list_kv("held:"):
            await self.submit(Alert.model_validate_json(value))
            await self.store.delete_kv(key)
            count += 1
        return count


def build_agent(settings: Settings) -> SOCAgent:
    policy = load_policy(settings.policy_path)
    safety = build_safety(settings)
    connectors = build_connectors(settings, safety)
    store = CaseStore(settings.db_path)
    return SOCAgent(settings, policy, connectors, store, safety)
