"""Response actions: planning targets from evidence, guardrails, and guarded execution."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .config import Settings
from .connectors.base import ActionOutcome, ConnectorError
from .models import (
    CONTAINMENT_ACTIONS,
    EFFECTIVE_STATUSES,
    REVERSAL_OF,
    ActionRecord,
    ActionStatus,
    ActionType,
    Case,
    IntelVerdict,
    User,
    utcnow,
)
from .policy import IRPolicy
from .utils import is_public_ip, truncate

if TYPE_CHECKING:
    from .connectors import Connectors
    from .safety import SafetySystem
    from .store import CaseStore

log = logging.getLogger("soc_agent.actions")

DEVICE_LEVEL = (
    ActionType.ISOLATE_DEVICE,
    ActionType.COLLECT_INVESTIGATION_PACKAGE,
    ActionType.RUN_AV_SCAN,
)
COUNTED_STATUSES = [ActionStatus.SUCCESS.value, ActionStatus.DRY_RUN.value, ActionStatus.TIMEOUT.value]
RETRYABLE = frozenset({ActionStatus.FAILED, ActionStatus.TIMEOUT})


class ActionPlanner:
    """Turns playbook action types into concrete, evidence-backed targets."""

    def __init__(self, policy: IRPolicy, *, allow_documentation_ips: bool) -> None:
        self.policy = policy
        self.allow_doc = allow_documentation_ips

    def plan(self, case: Case, action_types: list[ActionType], phase: str) -> list[ActionRecord]:
        existing = {(a.action, a.target) for a in case.actions if a.status not in RETRYABLE}
        limit = max(1, self.policy.guardrails.max_targets_per_action)
        planned: list[ActionRecord] = []

        def add(record: ActionRecord) -> None:
            if (record.action, record.target) in existing:
                return
            if sum(1 for r in planned if r.action == record.action) >= limit:
                return
            existing.add((record.action, record.target))
            planned.append(record)

        for action in action_types:
            if action in DEVICE_LEVEL:
                for dev in case.alert.devices:
                    rec = ActionRecord(action=action, target=dev.label, phase=phase,
                                       params={"device_id": dev.mde_id, "hostname": dev.hostname})
                    if not dev.mde_id:
                        rec.status = ActionStatus.SKIPPED
                        rec.reason = "device not found in Defender (not onboarded or offline)"
                    add(rec)
            elif action == ActionType.STOP_AND_QUARANTINE_FILE:
                intel = case.hash_verdicts()
                for f in case.alert.files:
                    summary = intel.get(f.best_hash or "")
                    if summary and summary.verdict == IntelVerdict.BENIGN:
                        continue
                    for dev in case.alert.devices:
                        rec = ActionRecord(action=action, target=f"{f.label} on {dev.label}", phase=phase,
                                           params={"device_id": dev.mde_id, "hostname": dev.hostname,
                                                   "sha1": f.sha1, "file": f.label})
                        if not dev.mde_id:
                            rec.status, rec.reason = ActionStatus.SKIPPED, "device not found in Defender"
                        elif not f.sha1:
                            rec.status, rec.reason = ActionStatus.SKIPPED, "Defender needs the SHA1 of the file"
                        add(rec)
            elif action == ActionType.BLOCK_IP:
                for ip, why in self._ip_candidates(case):
                    add(ActionRecord(action=action, target=ip, phase=phase, params={"ip": ip}, reason=why))
            elif action == ActionType.DISABLE_USER:
                for user in case.alert.users:
                    if not user.identifier:
                        continue
                    add(ActionRecord(action=action, target=user.identifier, phase=phase,
                                     params={"user": user.model_dump(mode="json")}))
        return planned

    def _ip_candidates(self, case: Case) -> list[tuple[str, str]]:
        g = self.policy.guardrails
        intel = case.ip_verdicts()
        malicious_file = any(s.verdict == IntelVerdict.MALICIOUS for s in case.hash_intel)
        suspect_contacts = {c.remote_ip for n in case.network for c in n.connections if c.from_suspect_process}
        candidates = list(case.alert.ips)
        for n in case.network:
            candidates.extend(ip for ip in n.c2_candidates if ip not in candidates)
        out: list[tuple[str, str]] = []
        skipped: list[str] = []
        for ip in candidates:
            if not is_public_ip(ip, allow_documentation=self.allow_doc) or self.policy.in_never_block(ip):
                continue
            s = intel.get(ip)
            verdict = s.verdict if s else IntelVerdict.UNKNOWN
            if verdict == IntelVerdict.MALICIOUS:
                out.append((ip, f"threat intel: malicious ({s.malicious_sources if s else 0} feeds)"))
            elif verdict == IntelVerdict.SUSPICIOUS and g.block_suspicious_ips:
                out.append((ip, "threat intel: suspicious (policy blocks suspicious IPs)"))
            elif (verdict in (IntelVerdict.UNKNOWN, IntelVerdict.SUSPICIOUS) and malicious_file
                  and g.block_unknown_ips_contacted_by_malware and ip in suspect_contacts):
                out.append((ip, "contacted by a confirmed-malicious process (likely C2)"))
            elif verdict != IntelVerdict.BENIGN:
                skipped.append(f"{ip} ({verdict.value})")
        if skipped:
            case.note("Not blocked (insufficient evidence): " + ", ".join(skipped))
        return out


class ActionExecutor:
    """Executes planned actions through IR guardrails, the safety gate and the connectors."""

    def __init__(self, settings: Settings, policy: IRPolicy, connectors: "Connectors", store: "CaseStore",
                 safety: "SafetySystem") -> None:
        self.settings = settings
        self.policy = policy
        self.c = connectors
        self.store = store
        self.safety = safety
        self._reserve_lock = asyncio.Lock()
        self._inflight: Counter[ActionType] = Counter()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        safety.kill_switch.add_listener(self._on_kill)

    # ------------------------------------------------------------------ kill switch hook

    def _on_kill(self, _state: Any) -> None:
        """Cancel every in-flight action the moment the kill switch engages (any thread)."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            self._cancel_all()
        else:
            loop.call_soon_threadsafe(self._cancel_all)

    def _cancel_all(self) -> None:
        for task in list(self._tasks):
            task.cancel()

    # ------------------------------------------------------------------ public API

    async def execute(self, case: Case, records: list[ActionRecord], timeout: float) -> None:
        self._loop = asyncio.get_running_loop()
        case.actions.extend(records)
        runnable: list[ActionRecord] = []
        for r in records:
            if r.status != ActionStatus.PENDING:
                r.finished_at = r.finished_at or utcnow()
                await self._audit(case, r, "action_not_run")
                continue
            if self.safety.kill_switch.engaged:
                self._finish(r, ActionStatus.BLOCKED, "KILL SWITCH engaged: no changes to any system. "
                                                      "A human must perform this action.")
                await self._audit(case, r, "action_blocked")
                continue
            decision = self._guardrails(case, r)
            if decision is not None:
                status, reason = decision
                self._finish(r, status, reason)
                await self._audit(case, r, "action_guardrail")
                continue
            if not await self._reserve(r.action):
                self._finish(r, ActionStatus.AWAITING_APPROVAL,
                             f"hourly limit for {r.action.value} reached (blast-radius guardrail); approve to proceed")
                await self._audit(case, r, "action_guardrail")
                continue
            runnable.append(r)
        await self._run(case, runnable, timeout, reserved=True)

    async def approve(self, case: Case, action_id: str, approver: str, timeout: float = 30.0) -> ActionRecord:
        self._loop = asyncio.get_running_loop()
        r = case.find_action(action_id)
        if r is None:
            raise LookupError(f"action {action_id} not found in {case.id}")
        if r.status != ActionStatus.AWAITING_APPROVAL:
            raise ValueError(f"action {action_id} is {r.status.value}, not awaiting approval")
        if self.safety.kill_switch.engaged:
            raise PermissionError("kill switch engaged: the agent will not execute any action")
        r.approved_by = approver
        r.reason = truncate(f"{r.reason} | approved by {approver}", 500)
        r.status = ActionStatus.PENDING
        await self.safety.audit.aappend("action_approved", {"case_id": case.id, "action_id": r.id,
                                                            "action": r.action.value, "target": r.target,
                                                            "approver": approver})
        async with self._reserve_lock:
            self._inflight[r.action] += 1
        await self._run(case, [r], timeout, reserved=True)
        return r

    async def rollback(self, case: Case, action_id: str, requested_by: str, *, phase: str = "rollback",
                       timeout: float = 30.0) -> ActionRecord:
        self._loop = asyncio.get_running_loop()
        original = case.find_action(action_id)
        if original is None:
            raise LookupError(f"action {action_id} not found in {case.id}")
        reverse = REVERSAL_OF.get(original.action)
        if reverse is None:
            raise ValueError(f"{original.action.value} cannot be rolled back")
        if original.status not in EFFECTIVE_STATUSES or original.rolled_back:
            raise ValueError(f"action {action_id} is not in an effective state to roll back")
        rb = ActionRecord(action=reverse, target=original.target, phase=phase, params=dict(original.params),
                          reason=f"rollback of {original.id} requested by {requested_by}")
        case.actions.append(rb)
        if self.safety.kill_switch.engaged:
            self._finish(rb, ActionStatus.BLOCKED, "KILL SWITCH engaged: perform the rollback manually")
            await self._audit(case, rb, "action_blocked")
            return rb
        await self._run(case, [rb], timeout, reserved=False)
        if rb.status in EFFECTIVE_STATUSES:
            original.rolled_back = True
        return rb

    # ------------------------------------------------------------------ internals

    def _finish(self, r: ActionRecord, status: ActionStatus, reason: str) -> None:
        r.status = status
        r.reason = truncate(reason, 500) if not r.reason else truncate(f"{r.reason} | {reason}", 500)
        r.finished_at = utcnow()

    def _guardrails(self, case: Case, r: ActionRecord) -> tuple[ActionStatus, str] | None:
        p = r.params
        if r.action == ActionType.ISOLATE_DEVICE and self.policy.is_protected_host(p.get("hostname")):
            return (ActionStatus.AWAITING_APPROVAL,
                    f"{p.get('hostname')} is a protected asset in the IR policy; isolation needs a human decision")
        if r.action == ActionType.DISABLE_USER:
            user = User.model_validate(p.get("user") or {})
            if self.policy.is_protected_account(user):
                return (ActionStatus.BLOCKED,
                        f"{user.identifier} is a protected (break-glass/emergency) account; the agent never disables it")
            ctx = case.context_for(user)
            if self.policy.is_privileged_account(user) or (ctx is not None and ctx.privileged):
                roles = f" ({', '.join(ctx.roles)})" if ctx and ctx.roles else ""
                return (ActionStatus.AWAITING_APPROVAL,
                        f"{user.identifier} is privileged{roles}; disabling requires human approval")
        if r.action == ActionType.BLOCK_IP:
            ip = str(p.get("ip") or "")
            if not is_public_ip(ip, allow_documentation=self.settings.mock_mode):
                return ActionStatus.BLOCKED, f"{ip} is not a public routable address"
            if self.policy.in_never_block(ip):
                return ActionStatus.BLOCKED, f"{ip} is on the never-block list"
        if r.action in self.policy.guardrails.approval_required_actions:
            return ActionStatus.AWAITING_APPROVAL, "IR policy requires approval for this action type"
        return None

    async def _reserve(self, action: ActionType) -> bool:
        limit = self.policy.hourly_limit(action)
        async with self._reserve_lock:
            if limit is not None:
                since = utcnow() - timedelta(hours=1)
                used = await self.store.count_actions_since(action.value, since, COUNTED_STATUSES)
                if used + self._inflight[action] >= limit:
                    return False
            self._inflight[action] += 1
            return True

    async def _run(self, case: Case, records: list[ActionRecord], timeout: float, *, reserved: bool) -> None:
        if not records:
            return
        tasks: dict[asyncio.Task[None], ActionRecord] = {}
        try:
            if timeout <= 0:
                for r in records:
                    self._finish(r, ActionStatus.TIMEOUT, "no time budget left; perform manually")
                return
            for r in records:
                task = asyncio.create_task(self._run_one(case, r))
                tasks[task] = r
                self._tasks.add(task)
            done, pending = await asyncio.wait(tasks.keys(), timeout=timeout)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task, r in tasks.items():
                if task.cancelled() or task in pending:
                    if r.status == ActionStatus.PENDING:
                        halted = self.safety.kill_switch.engaged
                        self._finish(
                            r, ActionStatus.BLOCKED if halted else ActionStatus.TIMEOUT,
                            "cancelled by KILL SWITCH; verify state in the console" if halted
                            else "no confirmation within the time budget; the request may still complete - verify",
                        )
        finally:
            for task in tasks:
                self._tasks.discard(task)
            for r in records:
                if r.status in (ActionStatus.SUCCESS, ActionStatus.DRY_RUN, ActionStatus.TIMEOUT):
                    await self.store.log_action(case.id, r)
                await self._audit(case, r, "action_result")
                if reserved:
                    self._inflight[r.action] = max(0, self._inflight[r.action] - 1)

    async def _run_one(self, case: Case, r: ActionRecord) -> None:
        r.started_at = utcnow()
        # Integrity re-check and the safety gate run immediately before the system call.
        if self.safety.monitor.check_integrity():
            self._finish(r, ActionStatus.BLOCKED, "SAFETY: agent code/policy changed at runtime; kill switch tripped")
            return
        decision = self.safety.gate.authorize(case, r)
        if not decision.allowed:
            self._finish(r, ActionStatus.BLOCKED, f"SAFETY: {decision.reason}")
            case.safety_notes.append(f"{r.action.value} → {r.target}: {decision.reason}")
            return
        if self.settings.effective_dry_run:
            self._finish(r, ActionStatus.DRY_RUN, f"DRY RUN: would {r.action.value.replace('_', ' ')} {r.target}")
            return
        try:
            outcome = await self._dispatch(case, r)
        except ConnectorError as exc:
            self._finish(r, ActionStatus.FAILED, str(exc))
            self.safety.monitor.record_connector_failure(r.action.value, str(exc), exc.status_code)
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("unexpected error executing %s", r.action.value)
            self._finish(r, ActionStatus.FAILED, f"unexpected error: {type(exc).__name__}")
            return
        r.status = ActionStatus.SUCCESS
        r.detail = truncate(outcome.detail, 500)
        r.params.update(outcome.data)
        r.finished_at = utcnow()

    def _comment(self, case: Case, r: ActionRecord) -> str:
        return truncate(f"SOC Agent {case.id} ({r.phase}): {case.alert.title}", 250)

    async def _dispatch(self, case: Case, r: ActionRecord) -> ActionOutcome:
        p = r.params
        comment = self._comment(case, r)
        if r.action in (ActionType.ISOLATE_DEVICE, ActionType.RELEASE_DEVICE, ActionType.STOP_AND_QUARANTINE_FILE,
                        ActionType.COLLECT_INVESTIGATION_PACKAGE, ActionType.RUN_AV_SCAN):
            if self.c.edr is None:
                raise ConnectorError("no EDR connector configured")
            device_id = str(p.get("device_id") or "")
            if r.action == ActionType.ISOLATE_DEVICE:
                return await self.c.edr.isolate_device(device_id, comment)
            if r.action == ActionType.RELEASE_DEVICE:
                return await self.c.edr.release_device(device_id, comment)
            if r.action == ActionType.STOP_AND_QUARANTINE_FILE:
                return await self.c.edr.stop_and_quarantine_file(device_id, str(p.get("sha1") or ""), comment)
            if r.action == ActionType.COLLECT_INVESTIGATION_PACKAGE:
                return await self.c.edr.collect_investigation_package(device_id, comment)
            return await self.c.edr.run_av_scan(device_id, comment)
        if r.action in (ActionType.BLOCK_IP, ActionType.UNBLOCK_IP):
            if self.c.firewall is None:
                raise ConnectorError("no firewall connector configured")
            ip = str(p.get("ip") or "")
            if r.action == ActionType.BLOCK_IP:
                return await self.c.firewall.block_ip(ip, self.settings.block_duration_seconds, comment)
            return await self.c.firewall.unblock_ip(ip, p)
        if r.action in (ActionType.DISABLE_USER, ActionType.ENABLE_USER):
            if self.c.identity is None:
                raise ConnectorError("no identity connector configured")
            user = User.model_validate(p.get("user") or {})
            if r.action == ActionType.DISABLE_USER:
                return await self.c.identity.disable_user(user)
            return await self.c.identity.enable_user(user, p)
        raise ConnectorError(f"unsupported action {r.action.value}")

    async def _audit(self, case: Case, r: ActionRecord, event: str) -> None:
        try:
            await self.safety.audit.aappend(event, {
                "case_id": case.id, "action_id": r.id, "action": r.action.value, "target": r.target,
                "phase": r.phase, "status": r.status.value, "reason": r.reason, "detail": r.detail,
                "approved_by": r.approved_by, "dry_run": self.settings.effective_dry_run,
                "containment": r.action in CONTAINMENT_ACTIONS,
            })
        except OSError as exc:
            log.critical("AUDIT LOG WRITE FAILED: %s", exc)
