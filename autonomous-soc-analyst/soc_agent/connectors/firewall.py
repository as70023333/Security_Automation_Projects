"""Perimeter firewall connectors.

PAN-OS : registers the IP with a tag via the User-ID XML API. Reference the tag in a
         Dynamic Address Group used as source AND destination of a deny rule. The API
         key should belong to an admin role limited to "User-ID agent" XML API access.
FortiGate: creates an address object and adds it to an address group referenced by a
         deny policy. Use a REST API admin profile limited to firewall address objects.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote
from xml.sax.saxutils import quoteattr

import httpx

from .base import ActionOutcome, ConnectorError, FirewallConnector
from .http import request

_TAG = re.compile(r"^[A-Za-z0-9_.\-]{1,127}$")


class PanOSFirewall(FirewallConnector):
    name = "Palo Alto Networks PAN-OS"

    def __init__(self, client: httpx.AsyncClient, *, host: str, api_key: str, tag: str) -> None:
        if not _TAG.match(tag):
            raise ValueError("PAN-OS block tag may only contain letters, digits, '.', '_' and '-'")
        self._client = client
        self._url = f"https://{host.strip().rstrip('/')}/api/"
        self._key = api_key
        self._tag = tag

    async def _uid(self, op: str, ip: str, timeout_seconds: int | None) -> None:
        timeout_attr = f" timeout={quoteattr(str(timeout_seconds))}" if timeout_seconds else ""
        cmd = (
            "<uid-message><version>2.0</version><type>update</type><payload>"
            f"<{op}><entry ip={quoteattr(ip)}><tag><member{timeout_attr}>{self._tag}</member></tag></entry></{op}>"
            "</payload></uid-message>"
        )
        resp = await request(
            self._client, "POST", self._url, service="PAN-OS User-ID",
            headers={"X-PAN-KEY": self._key}, data={"type": "user-id", "cmd": cmd}, expected=(200,),
        )
        assert resp is not None
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as exc:
            raise ConnectorError("PAN-OS: unparseable XML response") from exc
        if root.attrib.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())[:300]
            raise ConnectorError(f"PAN-OS rejected the request: {msg}")

    async def block_ip(self, ip: str, duration_seconds: int, comment: str) -> ActionOutcome:
        # PAN-OS caps tag timeouts at 30 days.
        timeout = max(1, min(int(duration_seconds), 2_592_000))
        await self._uid("register", ip, timeout)
        return ActionOutcome(detail=f"Tagged '{self._tag}' on PAN-OS (auto-expires in {timeout // 3600}h)")

    async def unblock_ip(self, ip: str, data: dict[str, Any]) -> ActionOutcome:
        await self._uid("unregister", ip, None)
        return ActionOutcome(detail=f"Removed tag '{self._tag}' on PAN-OS")


class FortiGateFirewall(FirewallConnector):
    name = "Fortinet FortiGate"

    def __init__(self, client: httpx.AsyncClient, *, host: str, token: str, group: str, vdom: str = "root") -> None:
        self._client = client
        self._base = f"https://{host.strip().rstrip('/')}/api/v2/cmdb/firewall"
        self._headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self._group = group
        self._params = {"vdom": vdom}

    @staticmethod
    def _object_name(ip: str) -> str:
        return f"soc-block-{ip.replace(':', '_')}"

    async def block_ip(self, ip: str, duration_seconds: int, comment: str) -> ActionOutcome:
        name = self._object_name(ip)
        prefix = 128 if ":" in ip else 32
        body = (
            {"name": name, "ip6": f"{ip}/{prefix}", "comment": comment[:255]}
            if ":" in ip
            else {"name": name, "subnet": f"{ip}/{prefix}", "comment": comment[:255]}
        )
        kind = "address6" if ":" in ip else "address"
        group_kind = "addrgrp6" if ":" in ip else "addrgrp"
        try:
            await request(self._client, "POST", f"{self._base}/{kind}", service="FortiGate address",
                          headers=self._headers, params=self._params, json_body=body, expected=(200,))
        except ConnectorError as exc:
            if not _already_exists(exc):
                raise
        try:
            await request(
                self._client, "POST", f"{self._base}/{group_kind}/{quote(self._group, safe='')}/member",
                service="FortiGate address group", headers=self._headers, params=self._params,
                json_body={"name": name}, expected=(200,),
            )
        except ConnectorError as exc:
            if not _already_exists(exc):
                raise
        return ActionOutcome(
            detail=f"Added {name} to FortiGate group {self._group} (remove manually or via rollback)",
            data={"object": name, "kind": kind, "group_kind": group_kind},
        )

    async def unblock_ip(self, ip: str, data: dict[str, Any]) -> ActionOutcome:
        name = data.get("object") or self._object_name(ip)
        kind = data.get("kind") or ("address6" if ":" in ip else "address")
        group_kind = data.get("group_kind") or ("addrgrp6" if ":" in ip else "addrgrp")
        await request(
            self._client, "DELETE",
            f"{self._base}/{group_kind}/{quote(self._group, safe='')}/member/{quote(name, safe='')}",
            service="FortiGate address group", headers=self._headers, params=self._params, expected=(200,),
        )
        try:
            await request(self._client, "DELETE", f"{self._base}/{kind}/{quote(name, safe='')}",
                          service="FortiGate address", headers=self._headers, params=self._params,
                          expected=(200,))
        except ConnectorError:
            pass  # object still referenced elsewhere; membership removal is what unblocks
        return ActionOutcome(detail=f"Removed {name} from FortiGate group {self._group}")


def _already_exists(exc: ConnectorError) -> bool:
    body = (exc.body or "").lower()
    if "already exist" in body or "duplicate" in body:
        return True
    try:
        parsed = json.loads(exc.body or "{}")
    except ValueError:
        return False
    return isinstance(parsed, dict) and parsed.get("error") in (-5, -15)

