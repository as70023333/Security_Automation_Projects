"""Microsoft Defender for Endpoint + Microsoft Graph (Entra ID) connectors.

Required application permissions (grant only what you use):
  WindowsDefenderATP: Machine.Isolate, Machine.StopAndQuarantine, Machine.CollectForensics,
                      Machine.Scan, Machine.Read.All, AdvancedQuery.Read.All, File.Read.All,
                      Ti.ReadWrite (only if firewall_provider=defender_indicator)
  Microsoft Graph:    User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory,
                      User.EnableDisableAccount.All, User.RevokeSessions.All,
                      SecurityAlert.Read.All (poller)
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

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
from ..utils import is_hex_hash, kql_str, normalize_hash, odata_str, parse_dt, parse_ip
from .base import ActionOutcome, ConnectorError, EDRConnector, FirewallConnector, IdentityConnector, IntelProvider
from .http import request, response_json

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MDE_DEVICE_ID = re.compile(r"^[0-9a-f]{40}$")


def _check_device_id(device_id: str) -> str:
    value = (device_id or "").strip().lower()
    if not MDE_DEVICE_ID.match(value):
        raise ConnectorError(f"'{device_id}' is not a valid Defender machine id")
    return value


class MicrosoftTokenProvider:
    """OAuth2 client-credentials tokens, cached per scope."""

    def __init__(
        self, client: httpx.AsyncClient, *, tenant_id: str, client_id: str, client_secret: str, login_base_url: str
    ) -> None:
        self._client = client
        self._tenant = tenant_id
        self._client_id = client_id
        self._secret = client_secret
        self._login = login_base_url.rstrip("/")
        self._cache: dict[str, tuple[str, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def token(self, scope: str) -> str:
        cached = self._cache.get(scope)
        if cached and cached[1] > time.monotonic():
            return cached[0]
        lock = self._locks.setdefault(scope, asyncio.Lock())
        async with lock:
            cached = self._cache.get(scope)
            if cached and cached[1] > time.monotonic():
                return cached[0]
            resp = await request(
                self._client,
                "POST",
                f"{self._login}/{quote(self._tenant, safe='')}/oauth2/v2.0/token",
                service="Entra ID token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._secret,
                    "scope": scope,
                },
                expected=(200,),
                retries=1,
            )
            assert resp is not None
            body = response_json(resp, "Entra ID token")
            token = body.get("access_token") if isinstance(body, dict) else None
            if not token:
                raise ConnectorError("Entra ID token: no access_token in response")
            expires_in = int(body.get("expires_in", 3599))
            self._cache[scope] = (token, time.monotonic() + max(60, expires_in - 300))
            return token

    async def headers(self, scope: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self.token(scope)}", "Content-Type": "application/json"}


# --------------------------------------------------------------------------- Defender EDR


class DefenderEDR(EDRConnector):
    name = "Microsoft Defender for Endpoint"

    def __init__(
        self, client: httpx.AsyncClient, tokens: MicrosoftTokenProvider, *, base_url: str, scope: str,
        isolation_type: str = "Full",
    ) -> None:
        self._client = client
        self._tokens = tokens
        self._base = base_url.rstrip("/")
        self._scope = scope
        self._isolation_type = isolation_type

    async def _machine_action(self, device_id: str, path: str, body: dict[str, Any], label: str) -> ActionOutcome:
        did = _check_device_id(device_id)
        try:
            resp = await request(
                self._client,
                "POST",
                f"{self._base}/api/machines/{did}/{path}",
                service=f"Defender {label}",
                headers=await self._tokens.headers(self._scope),
                json_body=body,
                expected=(200, 201),
            )
        except ConnectorError as exc:
            if exc.status_code == 400 and exc.body and "ActiveRequestAlreadyExists" in exc.body:
                return ActionOutcome(
                    detail=f"{label}: an identical request is already active on the device",
                    data={"already_active": True},
                )
            raise
        assert resp is not None
        payload = response_json(resp, f"Defender {label}")
        action_id = payload.get("id") if isinstance(payload, dict) else None
        status = payload.get("status") if isinstance(payload, dict) else None
        return ActionOutcome(
            detail=f"{label} submitted (machine action {action_id}, status {status})",
            data={"machine_action_id": action_id},
        )

    async def isolate_device(self, device_id: str, comment: str) -> ActionOutcome:
        return await self._machine_action(
            device_id, "isolate", {"Comment": comment, "IsolationType": self._isolation_type}, "Isolation"
        )

    async def release_device(self, device_id: str, comment: str) -> ActionOutcome:
        return await self._machine_action(device_id, "unisolate", {"Comment": comment}, "Release from isolation")

    async def stop_and_quarantine_file(self, device_id: str, sha1: str, comment: str) -> ActionOutcome:
        normalized = normalize_hash(sha1)
        if not normalized or normalized[0] != "sha1":
            raise ConnectorError("StopAndQuarantineFile requires a SHA1 hash")
        return await self._machine_action(
            device_id, "StopAndQuarantineFile", {"Comment": comment, "Sha1": normalized[1]}, "Stop & quarantine file"
        )

    async def collect_investigation_package(self, device_id: str, comment: str) -> ActionOutcome:
        return await self._machine_action(
            device_id, "collectInvestigationPackage", {"Comment": comment}, "Investigation package collection"
        )

    async def run_av_scan(self, device_id: str, comment: str) -> ActionOutcome:
        return await self._machine_action(
            device_id, "runAntiVirusScan", {"Comment": comment, "ScanType": "Quick"}, "Antivirus scan"
        )

    async def resolve_device(self, hostname: str) -> Device | None:
        name = hostname.strip().lower()
        if not name:
            return None
        filters = [f"computerDnsName eq '{odata_str(name)}'"]
        if "." not in name:
            filters.append(f"startswith(computerDnsName,'{odata_str(name)}.')")
        last_error: ConnectorError | None = None
        for flt in filters:
            try:
                resp = await request(
                    self._client,
                    "GET",
                    f"{self._base}/api/machines",
                    service="Defender device lookup",
                    headers=await self._tokens.headers(self._scope),
                    params={"$filter": flt, "$top": "5"},
                    expected=(200,),
                    retries=1,
                )
            except ConnectorError as exc:
                last_error = exc
                continue
            assert resp is not None
            items = (response_json(resp, "Defender device lookup") or {}).get("value") or []
            if items:
                items.sort(key=lambda m: str(m.get("lastSeen") or ""), reverse=True)
                m = items[0]
                return Device(
                    hostname=m.get("computerDnsName"),
                    mde_id=m.get("id"),
                    os=m.get("osPlatform"),
                    ip=m.get("lastIpAddress"),
                )
        if last_error is not None:
            raise last_error
        return None

    async def network_activity(self, device: Device, suspect_hashes: list[str], lookback_hours: int) -> NetworkSummary:
        query = build_network_query(device, suspect_hashes, lookback_hours)
        resp = await request(
            self._client,
            "POST",
            f"{self._base}/api/advancedqueries/run",
            service="Defender advanced hunting",
            headers=await self._tokens.headers(self._scope),
            json_body={"Query": query},
            expected=(200,),
        )
        assert resp is not None
        rows = (response_json(resp, "Defender advanced hunting") or {}).get("Results") or []
        connections: list[NetworkConnection] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = parse_ip(row.get("RemoteIP"))
            if not ip:
                continue
            connections.append(
                NetworkConnection(
                    remote_ip=ip,
                    ports=[p for p in (_as_int(x) for x in _as_list(row.get("Ports"))) if p is not None],
                    urls=[str(u) for u in _as_list(row.get("Urls")) if u],
                    processes=[str(p) for p in _as_list(row.get("Processes")) if p],
                    count=_as_int(row.get("Connections")) or 0,
                    first_seen=parse_dt(row.get("FirstSeen")),
                    last_seen=parse_dt(row.get("LastSeen")),
                    from_suspect_process=bool(_as_int(row.get("FromSuspect"))),
                )
            )
        return summarize_network(device.label, connections, lookback_hours)


def build_network_query(device: Device, suspect_hashes: list[str], lookback_hours: int) -> str:
    """KQL for public connections from a device, flagging those made by a suspect process.

    Every interpolated value is validated (hex hashes, 40-hex device ids) or escaped,
    so alert content cannot inject KQL.
    """
    hours = max(1, min(720, int(lookback_hours)))
    if device.mde_id and MDE_DEVICE_ID.match(device.mde_id):
        device_filter = f'DeviceId == "{device.mde_id}"'
    elif device.hostname:
        name = kql_str(device.hostname.lower())
        device_filter = f'(DeviceName =~ "{name}" or DeviceName startswith "{name}.")'
    else:
        raise ConnectorError("network query needs a device id or hostname")
    sha256s = [h.lower() for h in suspect_hashes if is_hex_hash(h) and len(h) == 64]
    sha1s = [h.lower() for h in suspect_hashes if is_hex_hash(h) and len(h) == 40]

    def kql_list(values: list[str]) -> str:
        return ", ".join(f'"{v}"' for v in values) if values else "dynamic([])"

    return "\n".join(
        [
            "DeviceNetworkEvents",
            f"| where Timestamp > ago({hours}h)",
            f"| where {device_filter}",
            '| where RemoteIPType == "Public"',
            f"| extend FromSuspect = InitiatingProcessSHA256 in~ ({kql_list(sha256s)})"
            f" or InitiatingProcessSHA1 in~ ({kql_list(sha1s)})",
            "| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),"
            " Ports = make_set(RemotePort, 10), Urls = make_set(RemoteUrl, 5),"
            " Processes = make_set(InitiatingProcessFileName, 10), FromSuspect = max(toint(FromSuspect))"
            " by RemoteIP",
            "| order by FromSuspect desc, Connections desc",
            "| take 25",
        ]
    )


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- Defender file profile (intel)


class DefenderFileIntel(IntelProvider):
    """Defender's own view of a file: prevalence, signer, Microsoft determination."""

    name = "Defender File Profile"
    indicator_types = frozenset({"hash"})

    def __init__(self, client: httpx.AsyncClient, tokens: MicrosoftTokenProvider, *, base_url: str, scope: str) -> None:
        self._client = client
        self._tokens = tokens
        self._base = base_url.rstrip("/")
        self._scope = scope

    def supports(self, indicator_type: str, value: str) -> bool:
        return indicator_type == "hash" and len(value) in (40, 64)

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        resp = await request(
            self._client,
            "GET",
            f"{self._base}/api/files/{value}",
            service=self.name,
            headers=await self._tokens.headers(self._scope),
            expected=(200,),
            allow_404=True,
        )
        if resp is None:
            return self.result(value, indicator_type, detail="file not seen in this tenant")
        f = response_json(resp, self.name) or {}
        attrs = {k: f.get(k) for k in ("sha1", "sha256", "md5") if f.get(k)}
        prevalence = _as_int(f.get("globalPrevalence")) or 0
        determination = str(f.get("determinationType") or "").strip()
        det_value = str(f.get("determinationValue") or "").strip()
        signer = f.get("signer")
        if determination and determination.lower() not in ("unknown", "clean", "none"):
            return self.result(
                value, indicator_type, found=True, verdict=IntelVerdict.MALICIOUS, score=85,
                labels=[x for x in (det_value, determination) if x],
                detail=f"Microsoft determination: {determination} {det_value}".strip(), attributes=attrs,
            )
        if f.get("isValidCertificate") and signer and prevalence >= 10000:
            return self.result(
                value, indicator_type, found=True, verdict=IntelVerdict.BENIGN, score=0,
                detail=f"Validly signed by {signer}; seen on {prevalence:,} devices worldwide", attributes=attrs,
            )
        return self.result(
            value, indicator_type, found=True, verdict=IntelVerdict.UNKNOWN,
            detail=f"Global prevalence {prevalence:,}; signer {signer or 'none'}", attributes=attrs,
        )


# --------------------------------------------------------------------------- Defender indicators (firewall)


class DefenderIndicatorFirewall(FirewallConnector):
    """Blocks IPs fleet-wide via Defender custom indicators (network protection)."""

    name = "Defender custom indicators"

    def __init__(self, client: httpx.AsyncClient, tokens: MicrosoftTokenProvider, *, base_url: str, scope: str) -> None:
        self._client = client
        self._tokens = tokens
        self._base = base_url.rstrip("/")
        self._scope = scope

    async def block_ip(self, ip: str, duration_seconds: int, comment: str) -> ActionOutcome:
        expires = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        resp = await request(
            self._client,
            "POST",
            f"{self._base}/api/indicators",
            service="Defender indicator",
            headers=await self._tokens.headers(self._scope),
            json_body={
                "indicatorValue": ip,
                "indicatorType": "IpAddress",
                "action": "Block",
                "title": f"SOC Agent block {ip}",
                "description": comment[:1000],
                "severity": "High",
                "expirationTime": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "generateAlert": True,
            },
            expected=(200, 201),
        )
        assert resp is not None
        body = response_json(resp, "Defender indicator") or {}
        indicator_id = body.get("id") if isinstance(body, dict) else None
        return ActionOutcome(
            detail=f"Defender block indicator {indicator_id} created (expires {expires:%Y-%m-%d %H:%M} UTC)",
            data={"indicator_id": indicator_id},
        )

    async def unblock_ip(self, ip: str, data: dict[str, Any]) -> ActionOutcome:
        indicator_id = data.get("indicator_id")
        if not indicator_id:
            raise ConnectorError("no Defender indicator id recorded for this block")
        await request(
            self._client,
            "DELETE",
            f"{self._base}/api/indicators/{quote(str(indicator_id), safe='')}",
            service="Defender indicator",
            headers=await self._tokens.headers(self._scope),
            expected=(200, 204),
        )
        return ActionOutcome(detail=f"Defender indicator {indicator_id} deleted")


# --------------------------------------------------------------------------- Entra ID (Graph)


class EntraIdentity(IdentityConnector):
    name = "Microsoft Entra ID"

    def __init__(
        self, client: httpx.AsyncClient, tokens: MicrosoftTokenProvider, *, graph_base_url: str,
        ad: IdentityConnector | None = None,
    ) -> None:
        self._client = client
        self._tokens = tokens
        self._base = graph_base_url.rstrip("/") + "/v1.0"
        self._ad = ad

    @staticmethod
    def _user_path(user: User) -> str:
        uid = user.object_id or user.upn
        if not uid:
            raise ConnectorError("user has no UPN or object id for Entra ID lookup")
        return quote(uid, safe="@")

    async def _get(self, path: str, params: dict[str, str] | None, service: str) -> Any:
        resp = await request(
            self._client, "GET", f"{self._base}{path}", service=service,
            headers=await self._tokens.headers(GRAPH_SCOPE), params=params, expected=(200,), retries=1,
        )
        assert resp is not None
        return response_json(resp, service)

    async def get_user_context(self, user: User, lookback_hours: int) -> UserContext:
        ctx = UserContext(user=user, source=self.name)
        path = self._user_path(user)
        profile = await self._get(
            f"/users/{path}",
            {"$select": "id,displayName,userPrincipalName,accountEnabled,jobTitle,department,onPremisesSyncEnabled"},
            "Graph user profile",
        )
        object_id = profile.get("id") or user.object_id
        ctx.user = user.model_copy(update={"object_id": object_id, "upn": user.upn or profile.get("userPrincipalName")})
        ctx.display_name = profile.get("displayName")
        ctx.enabled = profile.get("accountEnabled")
        ctx.job_title = profile.get("jobTitle")
        ctx.department = profile.get("department")
        ctx.on_prem_synced = profile.get("onPremisesSyncEnabled")
        since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        oid = odata_str(str(object_id))
        results = await asyncio.gather(
            self._get("/auditLogs/signIns", {"$filter": f"userId eq '{oid}' and createdDateTime ge {since}",
                                             "$top": "50"}, "Graph sign-in logs"),
            self._get("/auditLogs/directoryAudits",
                      {"$filter": f"initiatedBy/user/id eq '{oid}' and activityDateTime ge {since}", "$top": "25"},
                      "Graph directory audits"),
            self._get(f"/users/{quote(str(object_id), safe='')}/transitiveMemberOf/microsoft.graph.directoryRole",
                      {"$select": "displayName"}, "Graph directory roles"),
            return_exceptions=True,
        )
        sign_ins, audits, roles = results
        if isinstance(sign_ins, BaseException):
            ctx.errors.append(str(sign_ins))
        else:
            ctx.activities.extend(_parse_sign_in(s) for s in sign_ins.get("value") or [] if isinstance(s, dict))
        if isinstance(audits, BaseException):
            ctx.errors.append(str(audits))
        else:
            ctx.activities.extend(_parse_audit(a) for a in audits.get("value") or [] if isinstance(a, dict))
        if isinstance(roles, BaseException):
            ctx.errors.append(str(roles))
        else:
            ctx.roles = [str(r["displayName"]) for r in roles.get("value") or [] if isinstance(r, dict) and r.get("displayName")]
            ctx.privileged = bool(ctx.roles)
        if self._ad is not None and ctx.on_prem_synced:
            try:
                ad_ctx = await self._ad.get_user_context(ctx.user, lookback_hours)
                ctx.privileged = ctx.privileged or ad_ctx.privileged
                ctx.roles.extend(r for r in ad_ctx.roles if r not in ctx.roles)
            except ConnectorError as exc:
                ctx.errors.append(f"AD lookup: {exc}")
        return ctx

    async def disable_user(self, user: User) -> ActionOutcome:
        path = self._user_path(user)
        headers = await self._tokens.headers(GRAPH_SCOPE)
        data: dict[str, Any] = {}
        try:
            await request(self._client, "PATCH", f"{self._base}/users/{path}", service="Graph disable user",
                          headers=headers, json_body={"accountEnabled": False}, expected=(200, 204))
            detail = "Entra ID account disabled"
            data["disabled_in"] = "entra"
        except ConnectorError as exc:
            if self._ad is not None and _is_onprem_mastered(exc):
                outcome = await self._ad.disable_user(user)
                detail = f"{outcome.detail} (account is mastered on-premises)"
                data["disabled_in"] = "ad"
                data.update(outcome.data)
            else:
                raise
        try:
            await request(self._client, "POST", f"{self._base}/users/{path}/revokeSignInSessions",
                          service="Graph revoke sessions", headers=headers, expected=(200, 204))
            detail += "; all sign-in sessions and refresh tokens revoked"
        except ConnectorError as exc:
            detail += f"; WARNING: session revocation failed ({exc})"
        return ActionOutcome(detail=detail, data=data)

    async def enable_user(self, user: User, data: dict[str, Any]) -> ActionOutcome:
        if data.get("disabled_in") == "ad":
            if self._ad is None:
                raise ConnectorError("account was disabled in AD but no AD connector is configured")
            return await self._ad.enable_user(user, data)
        await request(self._client, "PATCH", f"{self._base}/users/{self._user_path(user)}",
                      service="Graph enable user", headers=await self._tokens.headers(GRAPH_SCOPE),
                      json_body={"accountEnabled": True}, expected=(200, 204))
        return ActionOutcome(detail="Entra ID account re-enabled")


def _is_onprem_mastered(exc: ConnectorError) -> bool:
    text = f"{exc} {exc.body or ''}".lower()
    return "on-premises" in text or "onpremise" in text or "directory sync" in text


def _parse_sign_in(s: dict[str, Any]) -> UserActivity:
    loc = s.get("location") or {}
    status = s.get("status") or {}
    code = status.get("errorCode")
    success = (code == 0) if code is not None else None
    risk = str(s.get("riskLevelDuringSignIn") or "").lower()
    city, country = loc.get("city"), loc.get("countryOrRegion")
    return UserActivity(
        timestamp=parse_dt(s.get("createdDateTime")),
        kind="sign_in",
        ip=parse_ip(s.get("ipAddress")),
        country=country or None,
        location=", ".join(x for x in (city, country) if x) or None,
        application=s.get("appDisplayName"),
        success=success,
        risk=risk if risk in ("low", "medium", "high") else None,
        detail=(status.get("failureReason") or "") if success is False else (s.get("clientAppUsed") or ""),
    )


def _parse_audit(a: dict[str, Any]) -> UserActivity:
    targets = a.get("targetResources") or []
    target = targets[0].get("displayName") if targets and isinstance(targets[0], dict) else None
    activity = a.get("activityDisplayName") or "directory change"
    return UserActivity(
        timestamp=parse_dt(a.get("activityDateTime")),
        kind="directory_change",
        success=str(a.get("result") or "").lower() == "success",
        detail=f"{activity}" + (f" → {target}" if target else ""),
        application=a.get("loggedByService"),
    )


# --------------------------------------------------------------------------- Graph alert source (poller)


class GraphAlertSource:
    """Reads new Defender XDR alerts from Graph ``security/alerts_v2``."""

    def __init__(self, client: httpx.AsyncClient, tokens: MicrosoftTokenProvider, *, graph_base_url: str) -> None:
        self._client = client
        self._tokens = tokens
        self._base = graph_base_url.rstrip("/") + "/v1.0"

    async def fetch_since(self, since: datetime, max_pages: int = 10) -> list[dict[str, Any]]:
        stamp = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        url: str | None = f"{self._base}/security/alerts_v2"
        params: dict[str, str] | None = {"$filter": f"createdDateTime gt {stamp}", "$top": "100"}
        alerts: list[dict[str, Any]] = []
        allowed_prefix = self._base + "/"
        for _ in range(max_pages):
            if url is None:
                break
            resp = await request(self._client, "GET", url, service="Graph alerts_v2",
                                 headers=await self._tokens.headers(GRAPH_SCOPE), params=params,
                                 expected=(200,), retries=1)
            assert resp is not None
            body = response_json(resp, "Graph alerts_v2") or {}
            alerts.extend(a for a in body.get("value") or [] if isinstance(a, dict))
            next_link = body.get("@odata.nextLink")
            # Only follow pagination links that stay on the Graph endpoint.
            url = next_link if isinstance(next_link, str) and next_link.startswith(allowed_prefix) else None
            params = None
        alerts.sort(key=lambda a: str(a.get("createdDateTime") or ""))
        return alerts
