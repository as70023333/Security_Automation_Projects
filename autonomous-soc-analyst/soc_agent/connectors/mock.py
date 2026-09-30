"""Simulated environment ("Contoso") used by mock mode, the simulator CLI and the tests.

All hashes are derived from labels (sha256("sim:...")) so they cannot collide with real
samples, and all "internet" IPs are RFC 5737 documentation addresses.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ..analysis import summarize_network
from ..models import (
    Device,
    IntelVerdict,
    NetworkConnection,
    NetworkSummary,
    ProviderResult,
    User,
    UserActivity,
    UserContext,
)
from .base import ActionOutcome, ConnectorError, EDRConnector, FirewallConnector, IdentityConnector, IntelProvider

M, S, B = IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS, IntelVerdict.BENIGN


def _sha256(label: str) -> str:
    return hashlib.sha256(f"sim:{label}".encode()).hexdigest()


def _sha1(label: str) -> str:
    return hashlib.sha1(f"sim:{label}".encode()).hexdigest()


@dataclass(frozen=True)
class SimFile:
    label: str
    name: str
    path: str

    @property
    def sha256(self) -> str:
        return _sha256(self.label)

    @property
    def sha1(self) -> str:
        return _sha1(self.label)


LOCKBIT = SimFile("lockbit-payload", "svch0st.exe", r"C:\Users\jdoe\AppData\Local\Temp\svch0st.exe")
QAKBOT = SimFile("qakbot-loader", "invoice_2026.exe", r"C:\Users\asmith\Downloads\invoice_2026.exe")
ADMIN_TOOL = SimFile("contoso-admin-toolkit", "AdminToolkit.exe", r"C:\Program Files\Contoso IT\AdminToolkit.exe")
MIMIKATZ = SimFile("mimikatz-variant", "lsass_helper.exe", r"C:\Windows\Temp\lsass_helper.exe")
UNKNOWN_BIN = SimFile("unknown-updater", "updater_x64.exe", r"C:\ProgramData\Updater\updater_x64.exe")

C2_LOCKBIT = "203.0.113.66"
C2_LOCKBIT_SECONDARY = "203.0.113.67"
C2_QAKBOT = "198.51.100.77"
ATTACKER_IP = "198.51.100.23"
CDN_IP = "192.0.2.10"
MS_LOGIN_IP = "20.190.160.20"
HOME_IP = "192.0.2.50"


def device_id(host: str) -> str:
    return hashlib.sha1(f"sim-device:{host}".encode()).hexdigest()


DEVICES = {
    "ws-fin-042": Device(hostname="ws-fin-042.contoso.com", mde_id=device_id("ws-fin-042"), os="Windows11", ip="10.10.4.42"),
    "ws-eng-017": Device(hostname="ws-eng-017.contoso.com", mde_id=device_id("ws-eng-017"), os="Windows11", ip="10.10.7.17"),
    "dc01": Device(hostname="dc01.contoso.com", mde_id=device_id("dc01"), os="WindowsServer2022", ip="10.10.0.10"),
    "srv-file-01": Device(hostname="srv-file-01.contoso.com", mde_id=device_id("srv-file-01"), os="WindowsServer2022"),
}

# indicator -> provider -> (verdict, score, labels, detail)
INTEL: dict[str, dict[str, tuple[IntelVerdict, int, list[str], str]]] = {
    LOCKBIT.sha256: {
        "VirusTotal": (M, 98, ["ransomware.lockbit/filecoder"], "61/72 engines malicious"),
        "MalwareBazaar": (M, 95, ["LockBit", "ransomware"], "Known malware sample (exe)"),
        "ThreatFox": (M, 90, ["LockBit"], "2 IOC record(s): payload"),
        "AlienVault OTX": (M, 70, ["LockBit 3.0 affiliate campaign"], "referenced in 6 OTX pulse(s)"),
        "Hybrid Analysis": (M, 100, ["LockBit"], "sandbox verdict: malicious, threat score 100"),
        "Defender File Profile": (M, 85, ["Ransom:Win32/LockBit"], "Microsoft determination: Malware"),
    },
    QAKBOT.sha256: {
        "VirusTotal": (M, 88, ["trojan.qakbot/qbot"], "44/72 engines malicious"),
        "MalwareBazaar": (M, 95, ["QakBot"], "Known malware sample (exe)"),
        "AlienVault OTX": (S, 40, ["QakBot resurgence"], "referenced in 1 OTX pulse(s)"),
        "Hybrid Analysis": (M, 90, ["QakBot"], "sandbox verdict: malicious, threat score 90"),
    },
    ADMIN_TOOL.sha256: {
        "VirusTotal": (B, 0, [], "0/72 engines malicious"),
        "Hybrid Analysis": (B, 0, [], "sandbox verdict: whitelisted"),
        "Defender File Profile": (B, 0, [], "Validly signed by Contoso Ltd IT; seen on 254,000 devices worldwide"),
    },
    MIMIKATZ.sha256: {
        "VirusTotal": (M, 94, ["hacktool.mimikatz"], "58/72 engines malicious"),
        "MalwareBazaar": (M, 95, ["Mimikatz"], "Known malware sample (exe)"),
        "Hybrid Analysis": (M, 95, ["Mimikatz"], "sandbox verdict: malicious, threat score 95"),
        "Defender File Profile": (M, 85, ["HackTool:Win64/Mimikatz"], "Microsoft determination: HackTool"),
    },
    C2_LOCKBIT: {
        "VirusTotal": (M, 70, ["LockBit C2"], "9/94 engines malicious"),
        "ThreatFox": (M, 90, ["LockBit"], "1 IOC record(s): botnet C&C"),
        "AbuseIPDB": (M, 88, [], "abuse confidence 88%, 214 report(s)"),
        "AlienVault OTX": (S, 40, ["LockBit infrastructure"], "referenced in 3 OTX pulse(s)"),
    },
    C2_QAKBOT: {
        "ThreatFox": (M, 85, ["QakBot"], "1 IOC record(s): botnet C&C"),
        "AbuseIPDB": (M, 76, [], "abuse confidence 76%, 57 report(s)"),
        "VirusTotal": (S, 40, [], "3/94 engines malicious"),
    },
    ATTACKER_IP: {
        "AbuseIPDB": (M, 100, ["brute-force"], "abuse confidence 100%, 1,302 report(s)"),
        "GreyNoise": (S, 55, ["internet scanner"], "mass internet scanner classified malicious"),
        "VirusTotal": (M, 66, [], "6/94 engines malicious"),
    },
    CDN_IP: {
        "GreyNoise": (B, 0, ["Example CDN"], "known business service (Example CDN)"),
        "VirusTotal": (B, 0, [], "0/94 engines malicious"),
    },
    MS_LOGIN_IP: {
        "GreyNoise": (B, 0, ["Microsoft"], "known business service (Microsoft)"),
    },
}

ATTRIBUTES: dict[str, dict[str, str]] = {
    f.sha256: {"sha1": f.sha1, "sha256": f.sha256} for f in (LOCKBIT, QAKBOT, ADMIN_TOOL, MIMIKATZ, UNKNOWN_BIN)
}

HASH_PROVIDERS = [
    "VirusTotal", "MalwareBazaar", "ThreatFox", "AlienVault OTX", "Hybrid Analysis", "MISP", "Defender File Profile",
]
IP_PROVIDERS = ["VirusTotal", "ThreatFox", "AlienVault OTX", "AbuseIPDB", "GreyNoise", "MISP"]


@dataclass
class SimUser:
    upn: str
    display_name: str
    job_title: str
    department: str
    roles: list[str] = field(default_factory=list)
    on_prem_synced: bool = False
    pattern: str = "normal"


USERS = {
    "jdoe@contoso.com": SimUser("jdoe@contoso.com", "John Doe", "Financial Analyst", "Finance"),
    "asmith@contoso.com": SimUser("asmith@contoso.com", "Alice Smith", "Software Engineer", "Engineering"),
    "mchen@contoso.com": SimUser("mchen@contoso.com", "Michael Chen", "Account Executive", "Sales", pattern="takeover"),
    "admin.kpatel@contoso.com": SimUser("admin.kpatel@contoso.com", "Kiran Patel (Admin)", "Cloud Administrator",
                                        "IT", roles=["Global Administrator"], pattern="takeover"),
    "breakglass@contoso.com": SimUser("breakglass@contoso.com", "Break Glass", "Emergency Access", "IT",
                                      roles=["Global Administrator"]),
    "svc-backup@contoso.com": SimUser("svc-backup@contoso.com", "Backup Service", "Service Account", "IT",
                                      on_prem_synced=True),
}

NETWORK: dict[str, list[dict[str, Any]]] = {
    "ws-fin-042": [
        {"ip": C2_LOCKBIT, "ports": [443], "process": LOCKBIT.name, "sha256": LOCKBIT.sha256, "count": 48,
         "urls": ["cdn-sync.invalid"]},
        {"ip": C2_LOCKBIT_SECONDARY, "ports": [8443], "process": LOCKBIT.name, "sha256": LOCKBIT.sha256, "count": 6},
        {"ip": CDN_IP, "ports": [443], "process": "msedge.exe", "sha256": _sha256("msedge"), "count": 120},
        {"ip": MS_LOGIN_IP, "ports": [443], "process": LOCKBIT.name, "sha256": LOCKBIT.sha256, "count": 2},
        {"ip": "10.10.20.5", "ports": [445], "process": LOCKBIT.name, "sha256": LOCKBIT.sha256, "count": 310},
    ],
    "ws-eng-017": [
        {"ip": C2_QAKBOT, "ports": [443, 8080], "process": QAKBOT.name, "sha256": QAKBOT.sha256, "count": 22},
        {"ip": CDN_IP, "ports": [443], "process": "chrome.exe", "sha256": _sha256("chrome"), "count": 75},
    ],
    "dc01": [
        {"ip": MS_LOGIN_IP, "ports": [443], "process": "AzureADConnect.exe", "sha256": _sha256("aadc"), "count": 40},
    ],
}


class MockWorld:
    """Mutable state of the simulated tenant (isolations, blocks, disabled users)."""

    def __init__(self, latency_scale: float = 1.0, seed: int | None = None) -> None:
        self.latency_scale = max(0.0, latency_scale)
        self._rng = random.Random(seed)
        self.isolated: set[str] = set()
        self.blocked: set[str] = set()
        self.disabled: set[str] = set()
        self.quarantined: list[tuple[str, str]] = []
        self.calls: list[tuple[str, str]] = []
        self.fail_actions: set[str] = set()  # test hook: action names that should fail

    async def latency(self, lo: float, hi: float) -> None:
        if self.latency_scale > 0:
            await asyncio.sleep(self._rng.uniform(lo, hi) * self.latency_scale)

    def maybe_fail(self, action: str) -> None:
        if action in self.fail_actions:
            raise ConnectorError(f"simulated failure for {action}")


def _short(host: str | None) -> str:
    return (host or "").split(".", 1)[0].lower()


def _device_by_id(device_id_: str) -> Device | None:
    return next((d for d in DEVICES.values() if d.mde_id == device_id_), None)


class MockEDR(EDRConnector):
    name = "Defender for Endpoint (simulated)"

    def __init__(self, world: MockWorld) -> None:
        self.world = world

    def _require(self, device_id_: str) -> Device:
        dev = _device_by_id(device_id_)
        if dev is None:
            raise ConnectorError(f"device {device_id_} not found")
        return dev

    async def resolve_device(self, hostname: str) -> Device | None:
        await self.world.latency(0.05, 0.2)
        dev = DEVICES.get(_short(hostname))
        return dev.model_copy() if dev else None

    async def isolate_device(self, device_id: str, comment: str) -> ActionOutcome:
        await self.world.latency(0.2, 0.6)
        self.world.maybe_fail("isolate_device")
        dev = self._require(device_id)
        self.world.isolated.add(device_id)
        self.world.calls.append(("isolate", device_id))
        return ActionOutcome(detail=f"Isolation submitted for {dev.hostname} (machine action sim-{device_id[:8]})",
                             data={"machine_action_id": f"sim-{device_id[:8]}"})

    async def release_device(self, device_id: str, comment: str) -> ActionOutcome:
        await self.world.latency(0.2, 0.5)
        dev = self._require(device_id)
        self.world.isolated.discard(device_id)
        self.world.calls.append(("release", device_id))
        return ActionOutcome(detail=f"Release from isolation submitted for {dev.hostname}")

    async def stop_and_quarantine_file(self, device_id: str, sha1: str, comment: str) -> ActionOutcome:
        await self.world.latency(0.2, 0.6)
        self.world.maybe_fail("stop_and_quarantine_file")
        dev = self._require(device_id)
        self.world.quarantined.append((device_id, sha1))
        self.world.calls.append(("quarantine", f"{device_id}:{sha1}"))
        return ActionOutcome(detail=f"Process stopped and file quarantined on {dev.hostname}")

    async def collect_investigation_package(self, device_id: str, comment: str) -> ActionOutcome:
        await self.world.latency(0.2, 0.5)
        dev = self._require(device_id)
        self.world.calls.append(("collect", device_id))
        return ActionOutcome(detail=f"Investigation package collection started on {dev.hostname}")

    async def run_av_scan(self, device_id: str, comment: str) -> ActionOutcome:
        await self.world.latency(0.2, 0.5)
        dev = self._require(device_id)
        self.world.calls.append(("av_scan", device_id))
        return ActionOutcome(detail=f"Quick antivirus scan started on {dev.hostname}")

    async def network_activity(self, device: Device, suspect_hashes: list[str], lookback_hours: int) -> NetworkSummary:
        await self.world.latency(0.8, 2.0)  # advanced hunting is the slowest enrichment call
        now = datetime.now(timezone.utc)
        suspects = {h.lower() for h in suspect_hashes}
        rows = NETWORK.get(_short(device.hostname), []) if device.hostname else []
        if not rows and device.mde_id:
            dev = _device_by_id(device.mde_id)
            rows = NETWORK.get(_short(dev.hostname), []) if dev else []
        connections: list[NetworkConnection] = []
        for row in rows:
            if row["ip"].startswith("10."):
                continue  # RemoteIPType == "Public" in the real query
            connections.append(NetworkConnection(
                remote_ip=row["ip"], ports=row["ports"], urls=row.get("urls", []), processes=[row["process"]],
                count=row["count"], first_seen=now - timedelta(hours=3), last_seen=now - timedelta(minutes=4),
                from_suspect_process=row["sha256"] in suspects,
            ))
        connections.sort(key=lambda c: (not c.from_suspect_process, -c.count))
        return summarize_network(device.label, connections, lookback_hours)


class MockIdentity(IdentityConnector):
    name = "Entra ID (simulated)"

    def __init__(self, world: MockWorld) -> None:
        self.world = world

    @staticmethod
    def _lookup(user: User) -> SimUser | None:
        for name in user.names():
            if name in USERS:
                return USERS[name]
            candidate = f"{name}@contoso.com"
            if "@" not in name and "\\" not in name and candidate in USERS:
                return USERS[candidate]
            if "\\" in name:
                sam = name.split("\\", 1)[1]
                if f"{sam}@contoso.com" in USERS:
                    return USERS[f"{sam}@contoso.com"]
        return None

    async def get_user_context(self, user: User, lookback_hours: int) -> UserContext:
        await self.world.latency(0.3, 0.9)
        sim = self._lookup(user)
        if sim is None:
            raise ConnectorError(f"user {user.identifier} not found in directory")
        now = datetime.now(timezone.utc)
        ctx = UserContext(
            user=user.model_copy(update={"upn": sim.upn}), display_name=sim.display_name,
            enabled=sim.upn not in self.world.disabled, job_title=sim.job_title, department=sim.department,
            on_prem_synced=sim.on_prem_synced, privileged=bool(sim.roles), roles=list(sim.roles), source=self.name,
        )
        home = UserActivity(ip=HOME_IP, country="US", location="Kansas City, US", application="Microsoft Teams",
                            success=True, detail="Browser")
        if sim.pattern == "takeover":
            ctx.activities.append(home.model_copy(update={"timestamp": now - timedelta(hours=3)}))
            for i in range(12):
                ctx.activities.append(UserActivity(
                    timestamp=now - timedelta(minutes=165 - i), ip=ATTACKER_IP, country="RU", location="Moscow, RU",
                    application="Office 365 Exchange Online", success=False,
                    detail="Invalid username or password or Invalid on-premise username or password."))
            ctx.activities.append(UserActivity(
                timestamp=now - timedelta(minutes=140), ip=ATTACKER_IP, country="RU", location="Moscow, RU",
                application="Office 365 Exchange Online", success=True, risk="high", detail="Browser"))
            ctx.activities.append(UserActivity(
                timestamp=now - timedelta(minutes=130), kind="directory_change", success=True,
                detail="User registered security info → Authenticator app", application="Authentication Methods"))
        else:
            for hours in (20, 9, 1):
                ctx.activities.append(home.model_copy(update={"timestamp": now - timedelta(hours=hours)}))
        return ctx

    async def disable_user(self, user: User) -> ActionOutcome:
        await self.world.latency(0.3, 0.8)
        self.world.maybe_fail("disable_user")
        sim = self._lookup(user)
        if sim is None:
            raise ConnectorError(f"user {user.identifier} not found in directory")
        self.world.disabled.add(sim.upn)
        self.world.calls.append(("disable", sim.upn))
        return ActionOutcome(detail="Entra ID account disabled; all sign-in sessions and refresh tokens revoked",
                             data={"disabled_in": "entra"})

    async def enable_user(self, user: User, data: dict[str, Any]) -> ActionOutcome:
        await self.world.latency(0.2, 0.5)
        sim = self._lookup(user)
        if sim is None:
            raise ConnectorError(f"user {user.identifier} not found in directory")
        self.world.disabled.discard(sim.upn)
        self.world.calls.append(("enable", sim.upn))
        return ActionOutcome(detail="Entra ID account re-enabled")


class MockFirewall(FirewallConnector):
    name = "Perimeter firewall (simulated)"

    def __init__(self, world: MockWorld) -> None:
        self.world = world

    async def block_ip(self, ip: str, duration_seconds: int, comment: str) -> ActionOutcome:
        await self.world.latency(0.2, 0.6)
        self.world.maybe_fail("block_ip")
        self.world.blocked.add(ip)
        self.world.calls.append(("block", ip))
        return ActionOutcome(detail=f"Added to dynamic block list (auto-expires in {duration_seconds // 3600}h)")

    async def unblock_ip(self, ip: str, data: dict[str, Any]) -> ActionOutcome:
        await self.world.latency(0.1, 0.3)
        self.world.blocked.discard(ip)
        self.world.calls.append(("unblock", ip))
        return ActionOutcome(detail="Removed from dynamic block list")


class MockIntelProvider(IntelProvider):
    def __init__(self, name: str, indicator_types: set[str], world: MockWorld, latency: tuple[float, float]) -> None:
        self.name = name
        self.indicator_types = frozenset(indicator_types)
        self.world = world
        self._latency = latency

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        await self.world.latency(*self._latency)
        entry = INTEL.get(value, {}).get(self.name)
        attrs = ATTRIBUTES.get(value, {}) if self.name in ("VirusTotal", "Defender File Profile") else {}
        if entry is None:
            return self.result(value, indicator_type, detail="no record", attributes=attrs)
        verdict, score, labels, detail = entry
        return self.result(value, indicator_type, found=True, verdict=verdict, score=score, labels=labels,
                           detail=detail, attributes=attrs)


def mock_intel_providers(world: MockWorld) -> list[IntelProvider]:
    latencies = {
        "VirusTotal": (0.3, 0.9), "MalwareBazaar": (0.2, 0.6), "ThreatFox": (0.2, 0.6), "AlienVault OTX": (0.4, 1.2),
        "Hybrid Analysis": (0.5, 1.4), "MISP": (0.1, 0.3), "Defender File Profile": (0.2, 0.5),
        "AbuseIPDB": (0.2, 0.6), "GreyNoise": (0.2, 0.5),
    }
    names = list(dict.fromkeys(HASH_PROVIDERS + IP_PROVIDERS))
    providers: list[IntelProvider] = []
    for name in names:
        types = set()
        if name in HASH_PROVIDERS:
            types.add("hash")
        if name in IP_PROVIDERS:
            types.add("ip")
        providers.append(MockIntelProvider(name, types, world, latencies.get(name, (0.2, 0.6))))
    return providers
