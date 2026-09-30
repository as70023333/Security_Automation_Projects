"""Runtime configuration, loaded from environment variables (prefix ``SOC_``) or ``.env``."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SOC_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ---- operating mode -------------------------------------------------------------
    mock_mode: bool = True
    """Simulated Defender / Entra / firewall / intel. No external systems are touched."""
    armed: bool = False
    """Live mode only: real containment actions require SOC_ARMED=true. Otherwise every
    action is recorded as a dry run. Mock mode is always 'armed' against the simulator."""
    dry_run: bool = False
    sla_seconds: float = 28.0
    mock_latency_scale: float = 1.0

    policy_path: str = "ir_policy.yaml"
    safety_policy_path: str = "safety.yaml"
    data_dir: str = "data"
    db_path: str = "data/soc_agent.db"
    reports_dir: str = "reports"
    worker_count: int = 4
    public_base_url: str | None = None

    # ---- API authentication ---------------------------------------------------------
    api_key: SecretStr | None = None
    """Used by SIEM webhooks and analysts (cases, approvals, rollbacks)."""
    admin_api_key: SecretStr | None = None
    """Separate key for safety endpoints (kill switch, safety status)."""
    webhook_hmac_secret: SecretStr | None = None

    # ---- Microsoft (Defender for Endpoint, Graph / Entra ID) ------------------------
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    login_base_url: str = "https://login.microsoftonline.com"
    graph_base_url: str = "https://graph.microsoft.com"
    mde_base_url: str = "https://api.securitycenter.microsoft.com"
    mde_scope: str = "https://api.securitycenter.microsoft.com/.default"
    isolation_type: Literal["Full", "Selective"] = "Full"
    identity_provider: Literal["entra", "ad", "hybrid"] = "entra"
    user_activity_lookback_hours: int = 24
    network_lookback_hours: int = 24

    # ---- on-prem Active Directory (LDAPS) -------------------------------------------
    ad_server: str | None = None
    ad_bind_user: str | None = None
    ad_bind_password: SecretStr | None = None
    ad_base_dn: str | None = None
    ad_use_ssl: bool = True

    # ---- firewall -------------------------------------------------------------------
    firewall_provider: Literal["none", "panos", "fortigate", "defender_indicator"] = "none"
    block_duration_seconds: int = 86400
    panos_host: str | None = None
    panos_api_key: SecretStr | None = None
    panos_block_tag: str = "soc-agent-block"
    panos_verify_tls: bool = True
    fortigate_host: str | None = None
    fortigate_token: SecretStr | None = None
    fortigate_block_group: str = "SOC-AGENT-BLOCK"
    fortigate_vdom: str = "root"
    fortigate_verify_tls: bool = True

    # ---- threat intelligence --------------------------------------------------------
    intel_provider_timeout: float = 6.0
    virustotal_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    greynoise_api_key: SecretStr | None = None
    hybrid_analysis_api_key: SecretStr | None = None
    misp_url: str | None = None
    misp_api_key: SecretStr | None = None
    misp_verify_tls: bool = True

    # ---- report summariser (optional, text only: never makes decisions) -------------
    anthropic_api_key: SecretStr | None = None
    llm_model: str = "claude-haiku-4-5-20251001"
    llm_timeout_seconds: float = 5.0

    # ---- SOC notifications ----------------------------------------------------------
    teams_webhook_url: str | None = None
    slack_webhook_url: str | None = None
    pagerduty_routing_key: SecretStr | None = None
    ticket_webhook_url: str | None = None

    # ---- safety / admin out-of-band alerting ----------------------------------------
    kill_switch_file: str = "data/KILL_SWITCH"
    kill_switch: bool = False
    """SOC_KILL_SWITCH=true halts all actions regardless of the kill file."""
    audit_log_path: str = "data/audit.jsonl"
    safety_state_path: str = "data/safety_state.json"
    integrity_manifest_path: str = "integrity.lock"
    admin_webhook_url: str | None = None
    """Teams/Slack-compatible webhook for the admin. Separate from SOC channels."""
    admin_webhook_format: Literal["teams", "slack", "json"] = "teams"
    admin_pagerduty_routing_key: SecretStr | None = None
    egress_extra_hosts: str = ""
    """Comma-separated extra hosts the agent may call (e.g. an internal proxy)."""

    # ---- Defender alert poller ------------------------------------------------------
    enable_poller: bool = False
    poll_interval_seconds: int = 30

    @field_validator("worker_count")
    @classmethod
    def _workers(cls, v: int) -> int:
        return max(1, min(32, v))

    @field_validator("sla_seconds")
    @classmethod
    def _sla(cls, v: float) -> float:
        if v < 5:
            raise ValueError("sla_seconds must be at least 5 seconds")
        return v

    @property
    def effective_dry_run(self) -> bool:
        """Actions are simulated unless explicitly armed (or running against mocks)."""
        if self.dry_run:
            return True
        if self.mock_mode:
            return False
        return not self.armed

    def secret(self, name: str) -> str | None:
        value = getattr(self, name, None)
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
            return raw or None
        return value or None

    @property
    def microsoft_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.secret("client_secret"))

    @property
    def ad_configured(self) -> bool:
        return bool(
            self.ad_server
            and self.ad_bind_user
            and self.secret("ad_bind_password")
            and self.ad_base_dn
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
