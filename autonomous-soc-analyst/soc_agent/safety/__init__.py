"""Safety layer: kill switch, action gate, egress allowlist, integrity, breakout guard, audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..config import Settings
from ..connectors.http import create_client
from .audit import AuditLog
from .egress import EgressGuard, build_allowlist
from .events import EventKind, SafetyPolicy, SecurityEvent, load_safety_policy
from .gate import SafetyGate
from .integrity import PACKAGE_DIR, IntegrityMonitor, tracked_files
from .killswitch import KillLevel, KillState, KillSwitch
from .monitor import AdminAlerter, SafetyMonitor
from .runtime_guard import RuntimeGuard

__all__ = [
    "AuditLog", "EgressGuard", "EventKind", "KillLevel", "KillState", "KillSwitch", "SafetyGate", "SafetyMonitor",
    "SafetyPolicy", "SafetySystem", "SecurityEvent", "build_safety",
]


@dataclass
class SafetySystem:
    policy: SafetyPolicy
    kill_switch: KillSwitch
    audit: AuditLog
    monitor: SafetyMonitor
    gate: SafetyGate
    egress: EgressGuard
    integrity: IntegrityMonitor
    admin_client: httpx.AsyncClient
    runtime_guard: RuntimeGuard | None = None
    clients: list[httpx.AsyncClient] = field(default_factory=list)

    def client(self, *, verify: bool = True, timeout: float = 10.0) -> httpx.AsyncClient:
        """All outbound HTTP clients must be created here (egress guard attached)."""
        c = create_client(request_hook=self.egress, verify=verify, timeout=timeout)
        self.clients.append(c)
        return c

    def install_runtime_guard(self, settings: Settings) -> bool:
        if not self.policy.runtime_guard.enabled:
            return False
        protected_files = [Path(settings.policy_path), Path(settings.safety_policy_path),
                           Path(settings.integrity_manifest_path)]
        guard = RuntimeGuard(
            protected_dirs=[PACKAGE_DIR],
            protected_files=protected_files,
            kill_file=Path(settings.kill_switch_file),
            append_only_files=[Path(settings.audit_log_path)],
            reporter=self.monitor.runtime_violation,
            block_process_spawn=self.policy.runtime_guard.block_process_spawn,
        )
        if guard.install():
            self.runtime_guard = guard
            return True
        return False

    async def aclose(self) -> None:
        for c in [*self.clients, self.admin_client]:
            await c.aclose()
        self.clients.clear()


def build_safety(settings: Settings) -> SafetySystem:
    policy = load_safety_policy(settings.safety_policy_path)
    kill_switch = KillSwitch(settings.kill_switch_file, env_engaged=settings.kill_switch)
    audit = AuditLog(settings.audit_log_path)
    integrity = IntegrityMonitor(tracked_files([settings.policy_path, settings.safety_policy_path]))
    alerter = AdminAlerter(settings, None, Path(settings.data_dir) / "ADMIN_ALERTS.log")
    monitor = SafetyMonitor(settings=settings, policy=policy, kill_switch=kill_switch, audit=audit, alerter=alerter,
                            integrity=integrity)
    egress = EgressGuard(build_allowlist(settings), monitor.egress_violation)
    admin_client = create_client(request_hook=egress, timeout=8.0)
    alerter.client = admin_client
    gate = SafetyGate(policy, kill_switch, monitor)
    return SafetySystem(policy=policy, kill_switch=kill_switch, audit=audit, monitor=monitor, gate=gate,
                        egress=egress, integrity=integrity, admin_client=admin_client)
