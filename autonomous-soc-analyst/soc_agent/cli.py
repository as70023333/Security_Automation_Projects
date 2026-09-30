"""Command line: python -m soc_agent <command>."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .config import Settings

log = logging.getLogger("soc_agent.cli")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")


def _sim_settings(base: Settings, workdir: Path, latency: float) -> Settings:
    return base.model_copy(update={
        "mock_mode": True, "dry_run": False, "db_path": ":memory:", "data_dir": str(workdir),
        "reports_dir": str(workdir / "reports"), "kill_switch_file": str(workdir / "KILL_SWITCH"),
        "kill_switch": False, "audit_log_path": str(workdir / "audit.jsonl"),
        "safety_state_path": str(workdir / "safety_state.json"), "mock_latency_scale": latency,
        "enable_poller": False,
    })


# ---------------------------------------------------------------------------- simulate


def _row(name: str, case: Any) -> str:
    acts = ", ".join(f"{a.action.value.replace('_', ' ')}={a.status.value}" for a in case.actions) or "none"
    return (f"{name:<19} {case.alert_class:<22} {case.verdict.value:<15} {case.severity.value:<13} "
            f"{case.status.value:<18} {case.routing.value:<10} {case.elapsed_seconds:>5.2f}s  {acts}")


async def _simulate(settings: Settings, names: list[str], show: bool) -> int:
    from .normalize import normalize
    from .orchestrator import build_agent
    from .scenarios import SCENARIOS

    agent = build_agent(settings)
    agent.safety.monitor.startup_checks(settings.safety_state_path, settings.integrity_manifest_path)
    print(f"{'SCENARIO':<19} {'CLASS':<22} {'VERDICT':<15} {'SEVERITY':<13} {'STATUS':<18} {'ROUTING':<10} "
          f"{'TIME':>6}  ACTIONS")
    worst = 0.0
    try:
        for name in names:
            source, payload = SCENARIOS[name]()
            for alert in normalize(source, payload):
                case = await agent.handle_alert(alert)
                worst = max(worst, case.elapsed_seconds or 0)
                print(_row(name, case))
                if show:
                    print("\n" + case.report_markdown + "\n" + "-" * 100)
    finally:
        await agent.safety.monitor.flush()
        await agent.aclose()
    print(f"\nSlowest case: {worst:.2f}s (SLA {agent.sla:.0f}s). Reports: {settings.reports_dir}/")
    return 0


# ---------------------------------------------------------------------------- admin


def _admin(settings: Settings, args: argparse.Namespace) -> int:
    from .safety.audit import AuditLog, verify_audit_log
    from .safety.integrity import tracked_files, write_manifest
    from .safety.killswitch import KillLevel, KillSwitch, clear_kill_file

    ks = KillSwitch(settings.kill_switch_file, env_engaged=settings.kill_switch)
    if args.admin_cmd == "status":
        print(json.dumps(ks.state().model_dump(mode="json"), indent=2))
        audit = AuditLog(settings.audit_log_path)
        events = [e for e in audit.tail(200) if e.get("type") == "security_event"][-10:]
        for e in events:
            d = e.get("data", {})
            print(f"{e.get('ts')}  {d.get('kind'):<24} {d.get('summary')}")
        return 0
    if args.admin_cmd == "kill":
        state = ks.engage(KillLevel(args.level), args.reason, args.by)
        AuditLog(settings.audit_log_path).append("kill_switch_engaged_by_admin",
                                                 {"level": args.level, "reason": args.reason, "by": args.by})
        print(f"Kill switch ENGAGED ({state.level.value if state.level else 'full'}): {state.reason}")
        return 0
    if args.admin_cmd == "resume":
        if not args.confirm:
            print("Refusing: re-read the admin alerts and audit log first, then pass --confirm.")
            return 2
        if settings.kill_switch:
            print("SOC_KILL_SWITCH is set in the environment; unset it to resume.")
            return 2
        cleared = clear_kill_file(settings.kill_switch_file)
        AuditLog(settings.audit_log_path).append("kill_switch_cleared_by_admin", {"by": args.by, "cleared": cleared})
        print("Kill switch cleared. The running agent resumes within ~1s and alerts the admin channel."
              if cleared else "Kill switch was not engaged.")
        return 0
    if args.admin_cmd == "seal":
        n = write_manifest(settings.integrity_manifest_path, tracked_files([settings.policy_path,
                                                                           settings.safety_policy_path]))
        print(f"Sealed {n} files into {settings.integrity_manifest_path}. Make it read-only for the service account.")
        return 0
    if args.admin_cmd == "verify-audit":
        ok, count, message = verify_audit_log(settings.audit_log_path)
        print(("OK: " if ok else "TAMPERING DETECTED: ") + message)
        return 0 if ok else 1
    return 2


# ---------------------------------------------------------------------------- check


def _check(settings: Settings) -> int:
    from .policy import load_policy
    from .safety.egress import build_allowlist
    from .safety.events import load_safety_policy
    from .safety.integrity import IntegrityMonitor, tracked_files

    problems = 0
    try:
        policy = load_policy(settings.policy_path)
        print(f"IR policy OK: {len(policy.alert_classes)} alert classes, SLA "
              f"{policy.sla_seconds or settings.sla_seconds:.0f}s")
    except Exception as exc:
        print(f"IR policy INVALID: {exc}")
        problems += 1
    try:
        sp = load_safety_policy(settings.safety_policy_path)
        print(f"Safety policy OK: {len(sp.allowed_actions)} allowed actions, trips on {len(sp.trip_on)} event kinds")
    except Exception as exc:
        print(f"Safety policy INVALID: {exc}")
        problems += 1
    mode = "MOCK (simulated tenant)" if settings.mock_mode else ("LIVE, ARMED" if not settings.effective_dry_run
                                                                  else "LIVE, DRY RUN (set SOC_ARMED=true to act)")
    print(f"Mode: {mode}")
    print("Egress allowlist: " + (", ".join(sorted(build_allowlist(settings))) or "(none)"))
    ok, issues = IntegrityMonitor(tracked_files([settings.policy_path, settings.safety_policy_path])).verify_manifest(
        settings.integrity_manifest_path)
    print("Integrity: " + ("matches sealed manifest" if ok else "; ".join(issues[:3])))
    if not settings.mock_mode:
        for key, label in (("api_key", "SOC_API_KEY"), ("admin_api_key", "SOC_ADMIN_API_KEY")):
            if not settings.secret(key):
                print(f"MISSING: {label}")
                problems += 1
        if not (settings.admin_webhook_url or settings.secret("admin_pagerduty_routing_key")):
            print("WARNING: no admin alert channel (SOC_ADMIN_WEBHOOK_URL / SOC_ADMIN_PAGERDUTY_ROUTING_KEY)")
        if not settings.microsoft_configured:
            print("WARNING: Microsoft credentials missing (SOC_TENANT_ID / SOC_CLIENT_ID / SOC_CLIENT_SECRET)")
        if not ok:
            print("WARNING: live mode will not act until the manifest is sealed (admin seal)")
    return 1 if problems else 0


# ---------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    from .scenarios import SCENARIOS

    parser = argparse.ArgumentParser(prog="soc_agent", description="Autonomous SOC Analyst (Tier-1)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="run the webhook API (and optional Defender poller)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)

    p_sim = sub.add_parser("simulate", help="run attack scenarios against the simulated tenant")
    p_sim.add_argument("scenario", nargs="?", default="all", choices=["all", *SCENARIOS])
    p_sim.add_argument("--latency", type=float, default=1.0, help="simulated API latency multiplier")
    p_sim.add_argument("--show-report", action="store_true")
    p_sim.add_argument("--out", default="sim_output", help="where reports and the audit log are written")

    sub.add_parser("check", help="validate configuration, policies and integrity")

    p_exp = sub.add_parser("export-scenarios", help="write scenario payloads as JSON (for curl tests)")
    p_exp.add_argument("directory")

    p_admin = sub.add_parser("admin", help="kill switch and integrity administration (run on the agent host)")
    admin_sub = p_admin.add_subparsers(dest="admin_cmd", required=True)
    p_kill = admin_sub.add_parser("kill", help="engage the kill switch")
    p_kill.add_argument("--level", choices=["actions", "full"], default="full")
    p_kill.add_argument("--reason", default="manual kill by admin")
    p_kill.add_argument("--by", default="admin CLI")
    p_resume = admin_sub.add_parser("resume", help="clear the kill switch (admin only, outside the agent process)")
    p_resume.add_argument("--confirm", action="store_true")
    p_resume.add_argument("--by", default="admin CLI")
    admin_sub.add_parser("status", help="kill switch state and recent security events")
    admin_sub.add_parser("seal", help="write the integrity manifest for the current code + policies")
    admin_sub.add_parser("verify-audit", help="verify the audit log hash chain")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    settings = Settings()

    if args.cmd == "serve":
        import uvicorn

        from .api import create_app

        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print("NOTE: binding beyond localhost; terminate TLS in front of this service.", file=sys.stderr)
        uvicorn.run(create_app(settings, install_runtime_guard=True), host=args.host, port=args.port,
                    log_level="info", access_log=True)
        return 0
    if args.cmd == "simulate":
        out = Path(args.out)
        if out.exists() and not out.is_dir():
            parser.error(f"--out {out} is not a directory")
        out.mkdir(parents=True, exist_ok=True)
        names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
        return asyncio.run(_simulate(_sim_settings(settings, out, args.latency), names, args.show_report))
    if args.cmd == "check":
        return _check(settings)
    if args.cmd == "export-scenarios":
        target = Path(args.directory)
        target.mkdir(parents=True, exist_ok=True)
        for name, fn in SCENARIOS.items():
            source, payload = fn()
            (target / f"{name}.{source}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote {len(SCENARIOS)} payloads to {target}/ (POST each to /webhooks/<source>)")
        return 0
    if args.cmd == "admin":
        return _admin(settings, args)
    return 2
