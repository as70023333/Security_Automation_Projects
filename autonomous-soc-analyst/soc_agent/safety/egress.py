"""Egress allowlist: the agent may only talk to the systems it was configured to use.

Every HTTP client is created with this guard as a request hook, so a request to any
other host (injected URL, exfiltration attempt, modified code) is refused *before* a
connection is made, reported to the admin, and trips the kill switch.
Enforce the same allowlist at the network layer (proxy / NSG / egress firewall) too:
this in-process guard is detection plus defence in depth, not the only wall.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit

import httpx

from ..config import Settings
from ..connectors.base import ConnectorError

INTEL_HOSTS = {
    "virustotal_api_key": ["www.virustotal.com"],
    "abusech_auth_key": ["mb-api.abuse.ch", "threatfox-api.abuse.ch"],
    "otx_api_key": ["otx.alienvault.com"],
    "abuseipdb_api_key": ["api.abuseipdb.com"],
    "greynoise_api_key": ["api.greynoise.io"],
    "hybrid_analysis_api_key": ["www.hybrid-analysis.com"],
}


class EgressViolation(ConnectorError):
    pass


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlsplit(url if "://" in url else f"https://{url}").hostname
    except ValueError:
        return None
    return host.lower() if host else None


def build_allowlist(settings: Settings) -> set[str]:
    hosts: set[str] = set()
    if not settings.mock_mode:
        if settings.microsoft_configured:
            for url in (settings.login_base_url, settings.graph_base_url, settings.mde_base_url):
                if h := _host(url):
                    hosts.add(h)
        for key, names in INTEL_HOSTS.items():
            if settings.secret(key):
                hosts.update(names)
        if settings.misp_url and settings.secret("misp_api_key"):
            if h := _host(settings.misp_url):
                hosts.add(h)
        if settings.firewall_provider == "panos" and settings.panos_host:
            if h := _host(settings.panos_host):
                hosts.add(h)
        if settings.firewall_provider == "fortigate" and settings.fortigate_host:
            if h := _host(settings.fortigate_host):
                hosts.add(h)
        if settings.ad_server and (h := _host(settings.ad_server)):
            hosts.add(h)  # informational: LDAP does not use httpx, restrict it at the network layer
    # Notification channels and the report summariser are allowed in every mode.
    for channel in (settings.teams_webhook_url, settings.slack_webhook_url, settings.ticket_webhook_url,
                    settings.admin_webhook_url):
        if h := _host(channel):
            hosts.add(h)
    if settings.secret("pagerduty_routing_key") or settings.secret("admin_pagerduty_routing_key"):
        hosts.add("events.pagerduty.com")
    if settings.secret("anthropic_api_key"):
        hosts.add("api.anthropic.com")
    for extra in settings.egress_extra_hosts.split(","):
        if extra.strip():
            hosts.add(extra.strip().lower())
    return hosts


class EgressGuard:
    def __init__(self, allowed_hosts: set[str], on_violation: Callable[[str, str], None]) -> None:
        self.allowed = {h.lower() for h in allowed_hosts}
        self._on_violation = on_violation
        self.violations = 0

    def is_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in self.allowed:
            return True
        return any(a.startswith("*.") and host.endswith(a[1:]) for a in self.allowed)

    async def __call__(self, request: httpx.Request) -> None:
        host = request.url.host or ""
        scheme = request.url.scheme
        if scheme != "https" or not self.is_allowed(host):
            self.violations += 1
            # Never include the query string: it may carry data being exfiltrated.
            target = f"{scheme}://{host}{request.url.path}"
            self._on_violation(host, target)
            raise EgressViolation(f"egress to {scheme}://{host} blocked by safety allowlist")
