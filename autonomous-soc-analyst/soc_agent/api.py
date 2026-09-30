"""HTTP API.

Analyst / SIEM (``X-API-Key`` or ``Authorization: Bearer``):
  POST /webhooks/{defender|sentinel|splunk|generic}   (or HMAC ``X-Signature-256: sha256=<hex>``)
  GET  /cases · GET /cases/{id} · GET /cases/{id}/report
  POST /cases/{id}/actions/{action_id}/approve   {"approver": "..."}
  POST /cases/{id}/actions/{action_id}/rollback  {"requested_by": "..."}

Admin (``X-Admin-Key``, a different key):
  GET  /admin/safety                 kill switch, recent security events, integrity, egress allowlist
  POST /admin/kill                   {"level": "actions"|"full", "reason": "...", "engaged_by": "..."}
  POST /admin/replay-held            re-submit alerts held during a full stop
  GET  /admin/audit?limit=50         tail + chain verification

There is intentionally NO resume endpoint: clearing the kill switch requires shell access
to the host (``python -m soc_agent admin resume --confirm``), so a compromised API key,
or the agent itself, can never switch the agent back on.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .config import Settings
from .normalize import NORMALIZERS, NormalizationError, normalize
from .orchestrator import AgentHalted, SOCAgent, build_agent
from .poller import DefenderPoller
from .safety.audit import verify_audit_log
from .safety.events import EventKind
from .safety.killswitch import KillLevel
from .models import Severity

log = logging.getLogger("soc_agent.api")
MAX_BODY = 1_000_000


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers=headers)


def _secret_eq(provided: str | None, expected: str | None) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("x-api-key")


def _case_json(case: Any) -> dict[str, Any]:
    data: dict[str, Any] = case.model_dump(mode="json", exclude={"alert": {"raw"}, "report_markdown": True})
    return data


def _case_brief(case: Any) -> dict[str, Any]:
    return {
        "case_id": case.id, "alert": case.alert.key, "class": case.alert_class, "verdict": case.verdict.value,
        "severity": case.severity.value, "status": case.status.value, "routing": case.routing.value,
        "elapsed_seconds": case.elapsed_seconds, "sla_met": case.sla_met, "summary": case.summary,
        "actions": [{"id": a.id, "action": a.action.value, "target": a.target, "status": a.status.value,
                     "reason": a.reason, "detail": a.detail} for a in case.actions],
    }


def create_app(settings: Settings, agent: SOCAgent | None = None, *, install_runtime_guard: bool = False) -> Starlette:
    if not settings.mock_mode:
        if not settings.secret("api_key") or not settings.secret("admin_api_key"):
            raise RuntimeError("live mode requires SOC_API_KEY and SOC_ADMIN_API_KEY")
        if settings.secret("api_key") == settings.secret("admin_api_key"):
            raise RuntimeError("SOC_ADMIN_API_KEY must differ from SOC_API_KEY")

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        the_agent = agent or build_agent(settings)
        app.state.agent = the_agent
        safety = the_agent.safety
        if install_runtime_guard and safety.install_runtime_guard(settings):
            log.info("runtime breakout guard installed")
        safety.monitor.startup_checks(settings.safety_state_path, settings.integrity_manifest_path)
        safety.monitor.start()
        await the_agent.start()
        poller = None
        if settings.enable_poller and the_agent.connectors.alert_source is not None:
            poller = DefenderPoller(the_agent, the_agent.connectors.alert_source, settings.poll_interval_seconds)
            poller.start()
        await safety.audit.aappend("agent_started", {"mock_mode": settings.mock_mode,
                                                     "dry_run": settings.effective_dry_run,
                                                     "connectors": the_agent.connectors.describe()})
        try:
            yield
        finally:
            if poller is not None:
                await poller.stop()
            await the_agent.stop()
            await safety.audit.aappend("agent_stopped", {})
            await safety.monitor.stop()
            safety.monitor.mark_clean_shutdown(settings.safety_state_path)
            await the_agent.aclose()

    def get_agent(request: Request) -> SOCAgent:
        return request.app.state.agent  # type: ignore[no-any-return]

    def analyst_ok(request: Request) -> bool:
        expected = settings.secret("api_key")
        if expected is None:
            return settings.mock_mode
        return _secret_eq(_bearer(request), expected)

    def admin_ok(request: Request) -> bool:
        expected = settings.secret("admin_api_key")
        if expected is None:
            return settings.mock_mode
        return _secret_eq(request.headers.get("x-admin-key"), expected)

    def unauthorized() -> JSONResponse:
        return _json({"error": "unauthorized"}, 401)

    async def read_json(request: Request) -> tuple[bytes, Any]:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY:
            raise ValueError("payload too large")
        body = await request.body()
        if len(body) > MAX_BODY:
            raise ValueError("payload too large")
        try:
            return body, json.loads(body or b"{}")
        except ValueError as exc:
            raise ValueError("body is not valid JSON") from exc

    # ------------------------------------------------------------------ routes

    async def health(request: Request) -> Response:
        agent_ = get_agent(request)
        kill = agent_.safety.kill_switch.state()
        return _json({"status": "halted" if kill.engaged else "ok", "mode": "mock" if settings.mock_mode else "live",
                      "armed": not settings.effective_dry_run, "kill_switch": kill.model_dump(mode="json")})

    async def webhook(request: Request) -> Response:
        source = request.path_params["source"]
        if source not in NORMALIZERS:
            return _json({"error": f"unknown source; use one of {sorted(NORMALIZERS)}"}, 404)
        try:
            body, payload = await read_json(request)
        except ValueError as exc:
            return _json({"error": str(exc)}, 413 if "large" in str(exc) else 400)
        secret = settings.secret("webhook_hmac_secret")
        signed_ok = False
        if secret:
            sig = request.headers.get("x-signature-256", "")
            expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            signed_ok = _secret_eq(sig, expected)
        if not (signed_ok or analyst_ok(request)):
            return unauthorized()
        agent_ = get_agent(request)
        kill = agent_.safety.kill_switch.state()
        if kill.halts_processing:
            return _json({"error": "agent halted by kill switch", "reason": kill.reason}, 503, {"Retry-After": "300"})
        try:
            alerts = normalize(source, payload)
        except (NormalizationError, ValueError) as exc:
            return _json({"error": f"could not normalise alert: {exc}"}, 422)
        if request.query_params.get("wait", "").lower() in ("1", "true", "yes"):
            try:
                cases = [await agent_.handle_alert(a) for a in alerts]
            except AgentHalted as exc:
                return _json({"error": "agent halted by kill switch", "reason": str(exc)}, 503, {"Retry-After": "300"})
            return _json({"cases": [_case_brief(c) for c in cases]}, 200)
        accepted = []
        for a in alerts:
            try:
                await agent_.submit(a)
                accepted.append(a.key)
            except AgentHalted as exc:
                return _json({"error": "agent halted by kill switch", "reason": str(exc)}, 503, {"Retry-After": "300"})
            except asyncio.QueueFull:
                return _json({"error": "queue full", "accepted": accepted}, 503, {"Retry-After": "30"})
        return _json({"accepted": accepted}, 202)

    async def list_cases(request: Request) -> Response:
        if not analyst_ok(request):
            return unauthorized()
        try:
            limit = int(request.query_params.get("limit", "50"))
        except ValueError:
            limit = 50
        return _json({"cases": await get_agent(request).store.list_cases(limit)})

    async def get_case(request: Request) -> Response:
        if not analyst_ok(request):
            return unauthorized()
        case = await get_agent(request).store.get_case(request.path_params["case_id"])
        return _json(_case_json(case)) if case else _json({"error": "case not found"}, 404)

    async def get_report(request: Request) -> Response:
        if not analyst_ok(request):
            return unauthorized()
        case = await get_agent(request).store.get_case(request.path_params["case_id"])
        if case is None:
            return _json({"error": "case not found"}, 404)
        return PlainTextResponse(case.report_markdown, media_type="text/markdown; charset=utf-8")

    async def _case_action(request: Request, kind: str) -> Response:
        if not analyst_ok(request):
            return unauthorized()
        try:
            _, body = await read_json(request)
        except ValueError as exc:
            return _json({"error": str(exc)}, 400)
        who_key = "approver" if kind == "approve" else "requested_by"
        who = str((body or {}).get(who_key) or "").strip() if isinstance(body, dict) else ""
        if not who:
            return _json({"error": f"'{who_key}' is required (who is taking this decision?)"}, 400)
        agent_ = get_agent(request)
        case_id, action_id = request.path_params["case_id"], request.path_params["action_id"]
        try:
            if kind == "approve":
                case = await agent_.approve_action(case_id, action_id, who[:120])
            else:
                case = await agent_.rollback_action(case_id, action_id, who[:120])
        except LookupError as exc:
            return _json({"error": str(exc)}, 404)
        except PermissionError as exc:
            return _json({"error": str(exc)}, 423)
        except ValueError as exc:
            return _json({"error": str(exc)}, 409)
        return _json(_case_brief(case))

    async def approve(request: Request) -> Response:
        return await _case_action(request, "approve")

    async def rollback(request: Request) -> Response:
        return await _case_action(request, "rollback")

    # ------------------------------------------------------------------ admin

    async def admin_safety(request: Request) -> Response:
        if not admin_ok(request):
            return unauthorized()
        agent_ = get_agent(request)
        s = agent_.safety
        guard = s.runtime_guard
        return _json({
            "kill_switch": s.kill_switch.state().model_dump(mode="json"),
            "recent_events": [e.model_dump(mode="json") for e in s.monitor.events[-50:]],
            "integrity_drift": s.integrity.drift(),
            "egress_allowlist": sorted(s.egress.allowed),
            "egress_violations": s.egress.violations,
            "gate": s.gate.stats,
            "runtime_guard": {"installed": guard is not None, "blocked": guard.blocked if guard else 0},
            "admin_alert_channel_configured": s.monitor.alerter.configured,
            "dry_run": settings.effective_dry_run,
        })

    async def admin_kill(request: Request) -> Response:
        if not admin_ok(request):
            return unauthorized()
        try:
            _, body = await read_json(request)
        except ValueError as exc:
            return _json({"error": str(exc)}, 400)
        body = body if isinstance(body, dict) else {}
        try:
            level = KillLevel(str(body.get("level") or "actions"))
        except ValueError:
            return _json({"error": "level must be 'actions' or 'full'"}, 400)
        reason = str(body.get("reason") or "manual kill via admin API")[:300]
        by = str(body.get("engaged_by") or "admin API")[:120]
        agent_ = get_agent(request)
        state = agent_.safety.kill_switch.engage(level, reason, by)
        agent_.safety.monitor.report(EventKind.ADMIN_ACTION, f"kill switch engaged by {by}: {reason}",
                                     {"level": level.value}, severity=Severity.HIGH)
        await agent_.safety.monitor.flush()
        return _json({"kill_switch": state.model_dump(mode="json"),
                      "resume": "python -m soc_agent admin resume --confirm   (on the agent host)"})

    async def admin_replay(request: Request) -> Response:
        if not admin_ok(request):
            return unauthorized()
        agent_ = get_agent(request)
        try:
            n = await agent_.replay_held()
        except AgentHalted as exc:
            return _json({"error": f"still halted: {exc}"}, 423)
        return _json({"replayed": n})

    async def admin_audit(request: Request) -> Response:
        if not admin_ok(request):
            return unauthorized()
        try:
            limit = max(1, min(500, int(request.query_params.get("limit", "50"))))
        except ValueError:
            limit = 50
        s = get_agent(request).safety
        ok, count, message = await asyncio.to_thread(verify_audit_log, s.audit.path)
        return _json({"chain_ok": ok, "entries": count, "message": message, "tail": s.audit.tail(limit)})

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/webhooks/{source}", webhook, methods=["POST"]),
        Route("/cases", list_cases, methods=["GET"]),
        Route("/cases/{case_id}", get_case, methods=["GET"]),
        Route("/cases/{case_id}/report", get_report, methods=["GET"]),
        Route("/cases/{case_id}/actions/{action_id}/approve", approve, methods=["POST"]),
        Route("/cases/{case_id}/actions/{action_id}/rollback", rollback, methods=["POST"]),
        Route("/admin/safety", admin_safety, methods=["GET"]),
        Route("/admin/kill", admin_kill, methods=["POST"]),
        Route("/admin/replay-held", admin_replay, methods=["POST"]),
        Route("/admin/audit", admin_audit, methods=["GET"]),
    ]
    return Starlette(routes=routes, lifespan=lifespan)
