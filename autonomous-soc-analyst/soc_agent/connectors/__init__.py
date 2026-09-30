"""Builds the connector set from settings (mock or live)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from ..config import Settings
from .base import EDRConnector, FirewallConnector, IdentityConnector, IntelProvider, Summarizer

if TYPE_CHECKING:
    from ..safety import SafetySystem
    from .microsoft import GraphAlertSource
    from .mock import MockWorld

log = logging.getLogger("soc_agent.connectors")


@dataclass
class Connectors:
    edr: EDRConnector | None
    identity: IdentityConnector | None
    firewall: FirewallConnector | None
    intel: list[IntelProvider]
    summarizer: Summarizer | None
    notify_client: httpx.AsyncClient | None
    alert_source: "GraphAlertSource | None" = None
    world: "MockWorld | None" = None
    notes: list[str] = field(default_factory=list)

    def describe(self) -> dict[str, object]:
        return {
            "edr": self.edr.name if self.edr else None,
            "identity": self.identity.name if self.identity else None,
            "firewall": self.firewall.name if self.firewall else None,
            "intel": [p.name for p in self.intel],
            "summarizer": self.summarizer.name if self.summarizer else None,
            "notes": self.notes,
        }


def build_connectors(settings: Settings, safety: "SafetySystem") -> Connectors:
    client = safety.client(timeout=10.0)
    summarizer: Summarizer | None = None
    if settings.secret("anthropic_api_key"):
        from .llm import AnthropicSummarizer

        summarizer = AnthropicSummarizer(client, api_key=settings.secret("anthropic_api_key") or "",
                                         model=settings.llm_model)

    if settings.mock_mode:
        from .mock import MockEDR, MockFirewall, MockIdentity, MockWorld, mock_intel_providers

        world = MockWorld(latency_scale=settings.mock_latency_scale)
        return Connectors(edr=MockEDR(world), identity=MockIdentity(world), firewall=MockFirewall(world),
                          intel=mock_intel_providers(world), summarizer=summarizer, notify_client=client,
                          world=world, notes=["MOCK MODE: simulated Contoso tenant, no real systems touched"])

    from . import intel_providers as ti
    from .active_directory import ActiveDirectoryIdentity
    from .firewall import FortiGateFirewall, PanOSFirewall
    from .microsoft import (
        DefenderEDR,
        DefenderFileIntel,
        DefenderIndicatorFirewall,
        EntraIdentity,
        GraphAlertSource,
        MicrosoftTokenProvider,
    )

    notes: list[str] = []
    edr: EDRConnector | None = None
    identity: IdentityConnector | None = None
    firewall: FirewallConnector | None = None
    intel: list[IntelProvider] = []
    alert_source = None

    ad: IdentityConnector | None = None
    if settings.identity_provider in ("ad", "hybrid"):
        if settings.ad_configured:
            ad = ActiveDirectoryIdentity(
                server=settings.ad_server or "", bind_user=settings.ad_bind_user or "",
                bind_password=settings.secret("ad_bind_password") or "", base_dn=settings.ad_base_dn or "",
                use_ssl=settings.ad_use_ssl,
            )
        else:
            notes.append("identity_provider requires AD but SOC_AD_* settings are incomplete")

    if settings.microsoft_configured:
        tokens = MicrosoftTokenProvider(client, tenant_id=settings.tenant_id or "", client_id=settings.client_id or "",
                                        client_secret=settings.secret("client_secret") or "",
                                        login_base_url=settings.login_base_url)
        edr = DefenderEDR(client, tokens, base_url=settings.mde_base_url, scope=settings.mde_scope,
                          isolation_type=settings.isolation_type)
        intel.append(DefenderFileIntel(client, tokens, base_url=settings.mde_base_url, scope=settings.mde_scope))
        if settings.identity_provider in ("entra", "hybrid"):
            identity = EntraIdentity(client, tokens, graph_base_url=settings.graph_base_url, ad=ad)
        alert_source = GraphAlertSource(client, tokens, graph_base_url=settings.graph_base_url)
        if settings.firewall_provider == "defender_indicator":
            firewall = DefenderIndicatorFirewall(client, tokens, base_url=settings.mde_base_url,
                                                 scope=settings.mde_scope)
    else:
        notes.append("Microsoft credentials missing: no EDR, Entra ID or Defender alert polling")
    if identity is None and ad is not None:
        identity = ad

    if settings.firewall_provider == "panos":
        if settings.panos_host and settings.secret("panos_api_key"):
            firewall = PanOSFirewall(safety.client(verify=settings.panos_verify_tls), host=settings.panos_host,
                                     api_key=settings.secret("panos_api_key") or "", tag=settings.panos_block_tag)
        else:
            notes.append("firewall_provider=panos but SOC_PANOS_HOST / SOC_PANOS_API_KEY missing")
    elif settings.firewall_provider == "fortigate":
        if settings.fortigate_host and settings.secret("fortigate_token"):
            firewall = FortiGateFirewall(safety.client(verify=settings.fortigate_verify_tls),
                                         host=settings.fortigate_host, token=settings.secret("fortigate_token") or "",
                                         group=settings.fortigate_block_group, vdom=settings.fortigate_vdom)
        else:
            notes.append("firewall_provider=fortigate but SOC_FORTIGATE_HOST / SOC_FORTIGATE_TOKEN missing")

    key = settings.secret
    if key("virustotal_api_key"):
        intel.append(ti.VirusTotal(client, key("virustotal_api_key") or ""))
    if key("abusech_auth_key"):
        intel.append(ti.MalwareBazaar(client, key("abusech_auth_key") or ""))
        intel.append(ti.ThreatFox(client, key("abusech_auth_key") or ""))
    if key("otx_api_key"):
        intel.append(ti.AlienVaultOTX(client, key("otx_api_key") or ""))
    if key("hybrid_analysis_api_key"):
        intel.append(ti.HybridAnalysis(client, key("hybrid_analysis_api_key") or ""))
    if key("abuseipdb_api_key"):
        intel.append(ti.AbuseIPDB(client, key("abuseipdb_api_key") or ""))
    if key("greynoise_api_key"):
        intel.append(ti.GreyNoise(client, key("greynoise_api_key") or ""))
    if settings.misp_url and key("misp_api_key"):
        misp_client = client if settings.misp_verify_tls else safety.client(verify=False)
        intel.append(ti.MISP(misp_client, settings.misp_url, key("misp_api_key") or ""))
    if not intel:
        notes.append("no threat-intel providers configured")

    for note in notes:
        log.warning(note)
    return Connectors(edr=edr, identity=identity, firewall=firewall, intel=intel, summarizer=summarizer,
                      notify_client=client, alert_source=alert_source, notes=notes)
