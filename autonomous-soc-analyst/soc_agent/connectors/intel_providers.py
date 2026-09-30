"""Live threat-intelligence providers. Each returns a scored ``ProviderResult``.

Adding a feed = subclass ``IntelProvider``, implement ``lookup`` and register it in
``connectors/__init__.py``. The aggregator handles timeouts, errors and consensus.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from ..models import IntelVerdict, ProviderResult
from .base import IntelProvider
from .http import request, response_json

M, S, B, U = IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS, IntelVerdict.BENIGN, IntelVerdict.UNKNOWN


class VirusTotal(IntelProvider):
    name = "VirusTotal"

    def __init__(self, client: httpx.AsyncClient, api_key: str) -> None:
        self._client, self._key = client, api_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        kind = "files" if indicator_type == "hash" else "ip_addresses"
        gui = "file" if indicator_type == "hash" else "ip-address"
        resp = await request(self._client, "GET", f"https://www.virustotal.com/api/v3/{kind}/{quote(value, safe='')}",
                             service=self.name, headers={"x-apikey": self._key}, expected=(200,), allow_404=True)
        ref = f"https://www.virustotal.com/gui/{gui}/{value}"
        if resp is None:
            return self.result(value, indicator_type, detail="not found", reference=ref)
        attrs = ((response_json(resp, self.name) or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious") or 0), int(stats.get("suspicious") or 0)
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"))
        labels = [label] if label else []
        detail = f"{mal}/{total} engines malicious"
        extra = {k: attrs.get(k) for k in ("sha1", "sha256", "md5") if attrs.get(k)}
        high, low = (10, 3) if indicator_type == "hash" else (5, 2)
        if mal >= high:
            return self.result(value, indicator_type, found=True, verdict=M, score=min(100, 60 + mal), labels=labels,
                               detail=detail, reference=ref, attributes=extra)
        if mal >= low or (mal + sus) >= low:
            return self.result(value, indicator_type, found=True, verdict=S, score=40 + 3 * mal, labels=labels,
                               detail=detail, reference=ref, attributes=extra)
        if mal >= 1:
            return self.result(value, indicator_type, found=True, verdict=S, score=25, labels=labels,
                               detail=detail, reference=ref, attributes=extra)
        verdict = B if total >= 20 else U
        return self.result(value, indicator_type, found=True, verdict=verdict, detail=detail, reference=ref,
                           attributes=extra)


class MalwareBazaar(IntelProvider):
    name = "MalwareBazaar"
    indicator_types = frozenset({"hash"})

    def __init__(self, client: httpx.AsyncClient, auth_key: str) -> None:
        self._client, self._key = client, auth_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        resp = await request(self._client, "POST", "https://mb-api.abuse.ch/api/v1/", service=self.name,
                             headers={"Auth-Key": self._key}, data={"query": "get_info", "hash": value},
                             expected=(200,))
        assert resp is not None
        body = response_json(resp, self.name) or {}
        status = body.get("query_status")
        if status != "ok":
            return self.result(value, indicator_type, detail=str(status or "no result"))
        item = (body.get("data") or [{}])[0] or {}
        labels = [x for x in [item.get("signature"), *(item.get("tags") or [])] if x][:5]
        attrs = {"sha1": item.get("sha1_hash"), "sha256": item.get("sha256_hash"), "md5": item.get("md5_hash")}
        return self.result(value, indicator_type, found=True, verdict=M, score=95, labels=labels,
                           detail=f"Known malware sample ({item.get('file_type') or 'file'}), first seen "
                                  f"{item.get('first_seen') or 'unknown'}",
                           reference=f"https://bazaar.abuse.ch/sample/{item.get('sha256_hash') or value}/",
                           attributes={k: v for k, v in attrs.items() if v})


class ThreatFox(IntelProvider):
    name = "ThreatFox"

    def __init__(self, client: httpx.AsyncClient, auth_key: str) -> None:
        self._client, self._key = client, auth_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        body_req: dict[str, Any] = (
            {"query": "search_hash", "hash": value}
            if indicator_type == "hash"
            else {"query": "search_ioc", "search_term": value}
        )
        resp = await request(self._client, "POST", "https://threatfox-api.abuse.ch/api/v1/", service=self.name,
                             headers={"Auth-Key": self._key}, json_body=body_req, expected=(200,))
        assert resp is not None
        body = response_json(resp, self.name) or {}
        data = body.get("data") if body.get("query_status") == "ok" else None
        items = [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []
        if indicator_type == "ip":
            items = [d for d in items if str(d.get("ioc", "")).split(":")[0] == value or d.get("ioc") == value]
        if not items:
            return self.result(value, indicator_type, detail="no IOC match")
        confidence = max(int(d.get("confidence_level") or 0) for d in items)
        labels = list(dict.fromkeys(str(d.get("malware_printable")) for d in items if d.get("malware_printable")))[:4]
        threat = items[0].get("threat_type_desc") or items[0].get("threat_type") or "IOC"
        verdict = M if confidence >= 50 else S
        return self.result(value, indicator_type, found=True, verdict=verdict, score=max(40, confidence),
                           labels=labels, detail=f"{len(items)} IOC record(s): {threat}",
                           reference=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(value)}")


class AlienVaultOTX(IntelProvider):
    name = "AlienVault OTX"

    def __init__(self, client: httpx.AsyncClient, api_key: str) -> None:
        self._client, self._key = client, api_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        section = "file" if indicator_type == "hash" else ("IPv6" if ":" in value else "IPv4")
        resp = await request(self._client, "GET",
                             f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value, safe='')}/general",
                             service=self.name, headers={"X-OTX-API-KEY": self._key}, expected=(200,),
                             allow_404=True)
        if resp is None:
            return self.result(value, indicator_type, detail="not found")
        pulse = (response_json(resp, self.name) or {}).get("pulse_info") or {}
        count = int(pulse.get("count") or 0)
        labels = [p.get("name") for p in (pulse.get("pulses") or [])[:3] if isinstance(p, dict) and p.get("name")]
        detail = f"referenced in {count} OTX pulse(s)"
        ref = f"https://otx.alienvault.com/indicator/{section.lower()}/{value}"
        hi, lo = (2, 1) if indicator_type == "hash" else (10, 2)
        if count >= hi:
            return self.result(value, indicator_type, found=True, verdict=M, score=70, labels=labels, detail=detail,
                               reference=ref)
        if count >= lo:
            return self.result(value, indicator_type, found=True, verdict=S, score=40, labels=labels, detail=detail,
                               reference=ref)
        return self.result(value, indicator_type, found=count > 0, detail=detail, reference=ref)


class HybridAnalysis(IntelProvider):
    name = "Hybrid Analysis"
    indicator_types = frozenset({"hash"})

    def __init__(self, client: httpx.AsyncClient, api_key: str) -> None:
        self._client, self._key = client, api_key

    def supports(self, indicator_type: str, value: str) -> bool:
        return indicator_type == "hash" and len(value) == 64

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        resp = await request(self._client, "GET", f"https://www.hybrid-analysis.com/api/v2/overview/{value}",
                             service=self.name,
                             headers={"api-key": self._key, "User-Agent": "Falcon Sandbox", "accept": "application/json"},
                             expected=(200,), allow_404=True)
        ref = f"https://www.hybrid-analysis.com/sample/{value}"
        if resp is None:
            return self.result(value, indicator_type, detail="not found", reference=ref)
        body = response_json(resp, self.name) or {}
        verdict_text = str(body.get("verdict") or "").lower()
        score = body.get("threat_score")
        family = body.get("vx_family")
        labels = [family] if family else []
        detail = f"sandbox verdict: {verdict_text or 'none'}" + (f", threat score {score}" if score is not None else "")
        if verdict_text == "malicious":
            return self.result(value, indicator_type, found=True, verdict=M, score=int(score or 85), labels=labels,
                               detail=detail, reference=ref)
        if verdict_text == "suspicious":
            return self.result(value, indicator_type, found=True, verdict=S, score=int(score or 50), labels=labels,
                               detail=detail, reference=ref)
        if verdict_text in ("no specific threat", "whitelisted", "no threat"):
            return self.result(value, indicator_type, found=True, verdict=B, detail=detail, reference=ref)
        return self.result(value, indicator_type, found=True, detail=detail, reference=ref)


class AbuseIPDB(IntelProvider):
    name = "AbuseIPDB"
    indicator_types = frozenset({"ip"})

    def __init__(self, client: httpx.AsyncClient, api_key: str) -> None:
        self._client, self._key = client, api_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        resp = await request(self._client, "GET", "https://api.abuseipdb.com/api/v2/check", service=self.name,
                             headers={"Key": self._key, "Accept": "application/json"},
                             params={"ipAddress": value, "maxAgeInDays": "90"}, expected=(200,))
        assert resp is not None
        d = (response_json(resp, self.name) or {}).get("data") or {}
        score = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        detail = f"abuse confidence {score}%, {reports} report(s); {d.get('isp') or 'unknown ISP'} ({d.get('countryCode') or '??'})"
        labels = ["Tor exit node"] if d.get("isTor") else []
        ref = f"https://www.abuseipdb.com/check/{value}"
        if d.get("isWhitelisted"):
            return self.result(value, indicator_type, found=True, verdict=B, detail=detail, reference=ref)
        if score >= 75:
            return self.result(value, indicator_type, found=True, verdict=M, score=score, labels=labels, detail=detail,
                               reference=ref)
        if score >= 25:
            return self.result(value, indicator_type, found=True, verdict=S, score=score, labels=labels, detail=detail,
                               reference=ref)
        return self.result(value, indicator_type, found=reports > 0, detail=detail, labels=labels, reference=ref)


class GreyNoise(IntelProvider):
    name = "GreyNoise"
    indicator_types = frozenset({"ip"})

    def __init__(self, client: httpx.AsyncClient, api_key: str) -> None:
        self._client, self._key = client, api_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        resp = await request(self._client, "GET", f"https://api.greynoise.io/v3/community/{quote(value, safe='')}",
                             service=self.name, headers={"key": self._key, "Accept": "application/json"},
                             expected=(200,), allow_404=True)
        ref = f"https://viz.greynoise.io/ip/{value}"
        if resp is None:
            return self.result(value, indicator_type, detail="not observed scanning the internet", reference=ref)
        d = response_json(resp, self.name) or {}
        name = d.get("name") or ""
        classification = str(d.get("classification") or "").lower()
        if d.get("riot"):
            return self.result(value, indicator_type, found=True, verdict=B, labels=[name] if name else [],
                               detail=f"known business service ({name or 'RIOT'})", reference=ref)
        if classification == "malicious":
            return self.result(value, indicator_type, found=True, verdict=S, score=55, labels=["internet scanner"],
                               detail="mass internet scanner classified malicious", reference=ref)
        if classification == "benign":
            return self.result(value, indicator_type, found=True, verdict=B, labels=[name] if name else [],
                               detail=f"benign scanner ({name})", reference=ref)
        return self.result(value, indicator_type, found=bool(d.get("noise")), detail=classification or "unknown",
                           reference=ref)


class MISP(IntelProvider):
    """Your internal / sharing-community intel (MISP)."""

    name = "MISP"

    def __init__(self, client: httpx.AsyncClient, url: str, api_key: str) -> None:
        self._client, self._url, self._key = client, url.rstrip("/"), api_key

    async def lookup(self, value: str, indicator_type: str) -> ProviderResult:
        resp = await request(self._client, "POST", f"{self._url}/attributes/restSearch", service=self.name,
                             headers={"Authorization": self._key, "Accept": "application/json"},
                             json_body={"returnFormat": "json", "value": value, "limit": 20}, expected=(200,))
        assert resp is not None
        attrs = (((response_json(resp, self.name) or {}).get("response") or {}).get("Attribute")) or []
        attrs = [a for a in attrs if isinstance(a, dict)]
        if not attrs:
            return self.result(value, indicator_type, detail="no MISP attribute")
        events = list(dict.fromkeys(str((a.get("Event") or {}).get("info") or "") for a in attrs if a.get("Event")))
        ids = any(bool(a.get("to_ids")) for a in attrs)
        return self.result(value, indicator_type, found=True, verdict=M if ids else S, score=85 if ids else 50,
                           labels=[e for e in events if e][:3],
                           detail=f"{len(attrs)} attribute(s) in {len(events)} event(s); IDS flag={'yes' if ids else 'no'}")
