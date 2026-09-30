"""Normalise alerts from Defender, Sentinel, Splunk or any SIEM into one ``Alert`` model."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from .models import Alert, Device, FileArtifact, Severity, User
from .utils import normalize_hash, parse_dt, parse_ip


class NormalizationError(ValueError):
    pass


class _Builder:
    """Collects entities while de-duplicating them."""

    def __init__(self) -> None:
        self.devices: list[Device] = []
        self.users: list[User] = []
        self.files: list[FileArtifact] = []
        self.ips: list[str] = []
        self.urls: list[str] = []

    def device(self, hostname: Any = None, mde_id: Any = None, os: Any = None, ip: Any = None) -> None:
        cand = Device(
            hostname=_s(hostname), mde_id=_s(mde_id), os=_s(os), ip=_s(ip) if parse_ip(ip) else None
        )
        if not (cand.hostname or cand.mde_id):
            return
        for existing in self.devices:
            same_id = cand.mde_id and existing.mde_id == cand.mde_id
            same_host = cand.hostname and existing.hostname and _short(existing.hostname) == _short(
                cand.hostname
            )
            if same_id or same_host:
                existing.hostname = existing.hostname or cand.hostname
                existing.mde_id = existing.mde_id or cand.mde_id
                existing.os = existing.os or cand.os
                existing.ip = existing.ip or cand.ip
                return
        self.devices.append(cand)

    def user(
        self,
        upn: Any = None,
        sam: Any = None,
        domain: Any = None,
        object_id: Any = None,
        display_name: Any = None,
    ) -> None:
        cand = User(
            upn=_s(upn) if _s(upn) and "@" in str(upn) else None,
            sam_account=_s(sam),
            domain=_s(domain),
            object_id=_s(object_id),
            display_name=_s(display_name),
        )
        if not cand.identifier:
            return
        for existing in self.users:
            if set(existing.names()) & set(cand.names()):
                for field in ("upn", "sam_account", "domain", "object_id", "display_name"):
                    if not getattr(existing, field) and getattr(cand, field):
                        setattr(existing, field, getattr(cand, field))
                return
        self.users.append(cand)

    def file(self, name: Any = None, path: Any = None, **hashes: Any) -> None:
        cand = FileArtifact(
            name=_s(name),
            path=_s(path),
            sha256=hashes.get("sha256"),
            sha1=hashes.get("sha1"),
            md5=hashes.get("md5"),
        )
        if not cand.hashes():
            return
        for existing in self.files:
            if set(existing.hashes()) & set(cand.hashes()):
                for field in ("name", "path", "sha256", "sha1", "md5"):
                    if not getattr(existing, field) and getattr(cand, field):
                        setattr(existing, field, getattr(cand, field))
                return
        self.files.append(cand)

    def file_hash(self, value: Any, name: Any = None) -> None:
        normalized = normalize_hash(value)
        if normalized:
            algo, digest = normalized
            self.file(name=name, **{algo: digest})

    def ip(self, value: Any) -> None:
        ip = parse_ip(value)
        if ip and ip not in self.ips:
            self.ips.append(ip)

    def url(self, value: Any) -> None:
        text = _s(value)
        if text and text not in self.urls:
            self.urls.append(text)

    def apply(self, alert_kwargs: dict[str, Any]) -> Alert:
        if alert_kwargs.get("created_at") is None:
            alert_kwargs.pop("created_at", None)
        return Alert(
            devices=self.devices,
            users=self.users,
            files=self.files,
            ips=self.ips,
            urls=self.urls,
            **alert_kwargs,
        )


def _s(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _short(host: str) -> str:
    return host.split(".", 1)[0].lower()


def _content_id(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:24]


# --------------------------------------------------------------------------- Defender


def from_defender(payload: dict[str, Any]) -> Alert:
    """Microsoft Defender XDR alert: Graph ``security/alerts_v2`` or legacy MDE ``/api/alerts``."""
    evidence = payload.get("evidence") or []
    if any(isinstance(e, dict) and "@odata.type" in e for e in evidence) or "createdDateTime" in payload:
        return _from_graph_alert(payload)
    return _from_mde_alert(payload)


def _from_graph_alert(d: dict[str, Any]) -> Alert:
    b = _Builder()
    for ev in d.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("@odata.type") or "").rsplit(".", 1)[-1]
        if kind == "deviceEvidence":
            ips = ev.get("ipInterfaces") or []
            b.device(ev.get("deviceDnsName"), ev.get("mdeDeviceId"), ev.get("osPlatform"), ips[0] if ips else None)
            for acct in ev.get("loggedOnUsers") or []:
                if isinstance(acct, dict):
                    b.user(sam=acct.get("accountName"), domain=acct.get("domainName"))
        elif kind in ("fileEvidence", "processEvidence"):
            details = ev.get("fileDetails") if kind == "fileEvidence" else ev.get("imageFile")
            details = details or {}
            b.file(
                details.get("fileName"),
                details.get("filePath"),
                sha256=details.get("sha256"),
                sha1=details.get("sha1"),
                md5=details.get("md5"),
            )
            acct = ev.get("userAccount")
            if isinstance(acct, dict):
                _graph_user(b, acct)
            if ev.get("mdeDeviceId"):
                b.device(mde_id=ev.get("mdeDeviceId"))
        elif kind == "userEvidence":
            acct = ev.get("userAccount")
            if isinstance(acct, dict):
                _graph_user(b, acct)
        elif kind == "ipEvidence":
            b.ip(ev.get("ipAddress"))
        elif kind == "urlEvidence":
            b.url(ev.get("url"))
    alert_id = _s(d.get("id")) or _content_id(d)
    return b.apply(
        dict(
            id=alert_id,
            source="defender",
            title=_s(d.get("title")) or "Microsoft Defender alert",
            description=_s(d.get("description")) or "",
            severity=Severity.parse(d.get("severity")),
            category=_s(d.get("category")),
            detection_source=_s(d.get("detectionSource")) or _s(d.get("serviceSource")),
            mitre_techniques=[str(t) for t in d.get("mitreTechniques") or []],
            created_at=parse_dt(d.get("createdDateTime")) or parse_dt(d.get("firstActivityDateTime")),
            raw=d,
        )
    )


def _graph_user(b: _Builder, acct: dict[str, Any]) -> None:
    b.user(
        upn=acct.get("userPrincipalName"),
        sam=acct.get("accountName"),
        domain=acct.get("domainName"),
        object_id=acct.get("azureAdUserId"),
        display_name=acct.get("displayName"),
    )


def _from_mde_alert(d: dict[str, Any]) -> Alert:
    b = _Builder()
    b.device(d.get("computerDnsName"), d.get("machineId"))
    rel = d.get("relatedUser")
    if isinstance(rel, dict):
        b.user(upn=rel.get("userPrincipalName"), sam=rel.get("userName"), domain=rel.get("domainName"))
    for ev in d.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("entityType") or "").lower()
        if kind in ("file", "process"):
            b.file(ev.get("fileName"), ev.get("filePath"), sha256=ev.get("sha256"), sha1=ev.get("sha1"))
        elif kind == "user":
            b.user(
                upn=ev.get("userPrincipalName"),
                sam=ev.get("accountName"),
                domain=ev.get("domainName"),
                object_id=ev.get("aadUserId"),
            )
        elif kind == "ip":
            b.ip(ev.get("ipAddress"))
        elif kind == "url":
            b.url(ev.get("url"))
    alert_id = _s(d.get("id")) or _content_id(d)
    return b.apply(
        dict(
            id=alert_id,
            source="defender",
            title=_s(d.get("title")) or "Microsoft Defender for Endpoint alert",
            description=_s(d.get("description")) or "",
            severity=Severity.parse(d.get("severity")),
            category=_s(d.get("category")),
            detection_source=_s(d.get("detectionSource")),
            mitre_techniques=[str(t) for t in d.get("mitreTechniques") or []],
            created_at=parse_dt(d.get("alertCreationTime")) or parse_dt(d.get("firstEventTime")),
            raw=d,
        )
    )


# --------------------------------------------------------------------------- Sentinel


def from_sentinel(payload: dict[str, Any]) -> Alert:
    """Sentinel incident (Logic App / automation rule trigger) or SecurityAlert record."""
    props = (payload.get("object") or {}).get("properties") if isinstance(payload.get("object"), dict) else None
    if isinstance(props, dict):
        return _from_sentinel_incident(payload, props)
    return _from_sentinel_alert(payload)


def _from_sentinel_incident(payload: dict[str, Any], p: dict[str, Any]) -> Alert:
    b = _Builder()
    for ent in p.get("relatedEntities") or []:
        if not isinstance(ent, dict):
            continue
        kind = str(ent.get("kind") or "").lower()
        ep = ent.get("properties") or {}
        extra = ep.get("additionalData") or {}
        if kind == "host":
            b.device(ep.get("hostName"), extra.get("MdatpDeviceId") or ep.get("mdatpDeviceId"), ep.get("osFamily"))
        elif kind == "account":
            upn = None
            if ep.get("accountName") and ep.get("upnSuffix"):
                upn = f"{ep['accountName']}@{ep['upnSuffix']}"
            b.user(upn=upn, sam=ep.get("accountName"), domain=ep.get("ntDomain"), object_id=ep.get("aadUserId"),
                   display_name=ep.get("displayName"))
        elif kind == "ip":
            b.ip(ep.get("address"))
        elif kind == "filehash":
            b.file_hash(ep.get("hashValue"))
        elif kind == "file":
            for h in ep.get("fileHashes") or []:
                if isinstance(h, dict):
                    b.file_hash(h.get("hashValue") or h.get("value"), name=ep.get("fileName"))
        elif kind == "url":
            b.url(ep.get("url"))
    number = p.get("incidentNumber")
    obj_name = (payload.get("object") or {}).get("name")
    alert_id = _s(obj_name) or (f"incident-{number}" if number is not None else _content_id(payload))
    extra = p.get("additionalData") or {}
    return b.apply(
        dict(
            id=alert_id,
            source="sentinel",
            title=_s(p.get("title")) or "Microsoft Sentinel incident",
            description=_s(p.get("description")) or "",
            severity=Severity.parse(p.get("severity")),
            category=(extra.get("tactics") or [None])[0] if isinstance(extra.get("tactics"), list) else None,
            detection_source=", ".join(extra.get("alertProductNames") or []) or "Microsoft Sentinel",
            mitre_techniques=[str(t) for t in extra.get("techniques") or []],
            created_at=parse_dt(p.get("createdTimeUtc")),
            raw=payload,
        )
    )


def _from_sentinel_alert(d: dict[str, Any]) -> Alert:
    b = _Builder()
    entities = d.get("Entities") or d.get("entities") or []
    if isinstance(entities, str):
        try:
            entities = json.loads(entities)
        except json.JSONDecodeError:
            entities = []
    for ent in entities if isinstance(entities, list) else []:
        if not isinstance(ent, dict):
            continue
        kind = str(ent.get("Type") or ent.get("type") or "").lower()
        if kind == "host":
            b.device(ent.get("HostName") or ent.get("FQDN"), ent.get("MdatpDeviceId"), ent.get("OSFamily"))
        elif kind == "account":
            upn = None
            if ent.get("Name") and ent.get("UPNSuffix"):
                upn = f"{ent['Name']}@{ent['UPNSuffix']}"
            b.user(upn=upn, sam=ent.get("Name"), domain=ent.get("NTDomain"), object_id=ent.get("AadUserId"),
                   display_name=ent.get("DisplayName"))
        elif kind == "ip":
            b.ip(ent.get("Address"))
        elif kind == "filehash":
            b.file_hash(ent.get("Value"))
        elif kind == "file":
            for h in ent.get("FileHashes") or []:
                if isinstance(h, dict):
                    b.file_hash(h.get("Value"), name=ent.get("Name"))
        elif kind == "url":
            b.url(ent.get("Url"))
    tactics = d.get("Tactics")
    category = tactics.split(",")[0].strip() if isinstance(tactics, str) and tactics else None
    techniques = d.get("Techniques") or []
    if isinstance(techniques, str):
        try:
            techniques = json.loads(techniques)
        except json.JSONDecodeError:
            techniques = [t.strip() for t in techniques.split(",") if t.strip()]
    alert_id = _s(d.get("SystemAlertId")) or _s(d.get("AlertId")) or _content_id(d)
    return b.apply(
        dict(
            id=alert_id,
            source="sentinel",
            title=_s(d.get("DisplayName")) or _s(d.get("AlertName")) or "Microsoft Sentinel alert",
            description=_s(d.get("Description")) or "",
            severity=Severity.parse(d.get("Severity") or d.get("AlertSeverity")),
            category=_s(d.get("Category")) or category,
            detection_source=_s(d.get("ProductName")) or "Microsoft Sentinel",
            mitre_techniques=[str(t) for t in techniques] if isinstance(techniques, list) else [],
            created_at=parse_dt(d.get("TimeGenerated")) or parse_dt(d.get("StartTime")),
            raw=d,
        )
    )


# --------------------------------------------------------------------------- Splunk


def from_splunk(payload: dict[str, Any]) -> Alert:
    """Splunk alert webhook action (``result`` holds the triggering event, CIM field names)."""
    result = payload.get("result")
    r: dict[str, Any] = result if isinstance(result, dict) else payload
    b = _Builder()
    b.device(r.get("dest_host") or r.get("dest_nt_host") or r.get("dest") or r.get("host"))
    user = r.get("user") or r.get("src_user")
    if user:
        text = str(user)
        if "\\" in text:
            domain, sam = text.split("\\", 1)
            b.user(sam=sam, domain=domain)
        elif "@" in text:
            b.user(upn=text, sam=text.split("@", 1)[0])
        else:
            b.user(sam=text)
    for field in ("src", "src_ip", "dest_ip", "remote_ip"):
        b.ip(r.get(field))
    for field in ("file_hash", "file_hash_sha256", "sha256", "sha1", "md5", "hash"):
        b.file_hash(r.get(field), name=r.get("file_name"))
    b.url(r.get("url"))
    sid = _s(payload.get("sid"))
    alert_id = f"{sid}:{_content_id(r)[:8]}" if sid else _content_id(payload)
    mitre = r.get("annotations.mitre_attack") or r.get("mitre_technique_id") or []
    if isinstance(mitre, str):
        mitre = [m.strip() for m in mitre.split(",") if m.strip()]
    return b.apply(
        dict(
            id=alert_id,
            source="splunk",
            title=_s(r.get("signature")) or _s(payload.get("search_name")) or "Splunk alert",
            description=_s(r.get("description")) or _s(r.get("rule_description")) or "",
            severity=Severity.parse(r.get("severity") or r.get("urgency")),
            category=_s(r.get("category")),
            detection_source=_s(payload.get("search_name")) or "Splunk",
            mitre_techniques=mitre if isinstance(mitre, list) else [],
            created_at=parse_dt(r.get("_time")),
            raw=payload,
        )
    )


# --------------------------------------------------------------------------- generic


def from_generic(payload: dict[str, Any]) -> Alert:
    """Any other SIEM (QRadar, Elastic, Chronicle...): post the documented generic schema."""
    b = _Builder()
    for d in payload.get("devices") or []:
        if isinstance(d, dict):
            b.device(d.get("hostname"), d.get("mde_id"), d.get("os"), d.get("ip"))
        elif isinstance(d, str):
            b.device(hostname=d)
    for u in payload.get("users") or []:
        if isinstance(u, dict):
            b.user(u.get("upn"), u.get("sam_account"), u.get("domain"), u.get("object_id"), u.get("display_name"))
        elif isinstance(u, str):
            b.user(upn=u) if "@" in u else b.user(sam=u)
    for f in payload.get("files") or []:
        if isinstance(f, dict):
            b.file(f.get("name"), f.get("path"), sha256=f.get("sha256"), sha1=f.get("sha1"), md5=f.get("md5"))
            b.file_hash(f.get("hash"), name=f.get("name"))
        elif isinstance(f, str):
            b.file_hash(f)
    for ip in payload.get("ips") or []:
        b.ip(ip)
    for url in payload.get("urls") or []:
        b.url(url)
    title = _s(payload.get("title"))
    if not title:
        raise NormalizationError("generic alerts require a 'title'")
    return b.apply(
        dict(
            id=_s(payload.get("id")) or _content_id(payload),
            source=_s(payload.get("source")) or "generic",
            title=title,
            description=_s(payload.get("description")) or "",
            severity=Severity.parse(payload.get("severity")),
            category=_s(payload.get("category")),
            detection_source=_s(payload.get("detection_source")),
            mitre_techniques=[str(t) for t in payload.get("mitre_techniques") or []],
            created_at=parse_dt(payload.get("created_at")),
            raw=payload,
        )
    )


NORMALIZERS: dict[str, Callable[[dict[str, Any]], Alert]] = {
    "defender": from_defender,
    "sentinel": from_sentinel,
    "splunk": from_splunk,
    "generic": from_generic,
}


def normalize(source: str, payload: Any) -> list[Alert]:
    """Normalise one payload (or a list / Graph ``{"value": [...]}`` page) into alerts."""
    fn = NORMALIZERS.get(source)
    if fn is None:
        raise NormalizationError(f"unknown alert source '{source}' (use one of {sorted(NORMALIZERS)})")
    if isinstance(payload, dict) and isinstance(payload.get("value"), list):
        items = payload["value"]
    elif isinstance(payload, list):
        items = payload
    else:
        items = [payload]
    alerts: list[Alert] = []
    for item in items:
        if not isinstance(item, dict):
            raise NormalizationError("each alert must be a JSON object")
        alerts.append(fn(item))
    return alerts
