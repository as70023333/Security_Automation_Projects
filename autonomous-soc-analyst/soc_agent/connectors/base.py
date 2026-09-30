"""Connector interfaces. Live and mock implementations share these contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from ..models import Device, NetworkSummary, ProviderResult, User, UserContext


class ConnectorError(Exception):
    """A connector call failed. The message is safe to show in reports (no secrets)."""

    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class ActionOutcome(BaseModel):
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)


class EDRConnector(ABC):
    name = "edr"

    @abstractmethod
    async def resolve_device(self, hostname: str) -> Device | None: ...

    @abstractmethod
    async def isolate_device(self, device_id: str, comment: str) -> ActionOutcome: ...

    @abstractmethod
    async def release_device(self, device_id: str, comment: str) -> ActionOutcome: ...

    @abstractmethod
    async def stop_and_quarantine_file(self, device_id: str, sha1: str, comment: str) -> ActionOutcome: ...

    @abstractmethod
    async def collect_investigation_package(self, device_id: str, comment: str) -> ActionOutcome: ...

    @abstractmethod
    async def run_av_scan(self, device_id: str, comment: str) -> ActionOutcome: ...

    @abstractmethod
    async def network_activity(
        self, device: Device, suspect_hashes: list[str], lookback_hours: int
    ) -> NetworkSummary: ...

    async def aclose(self) -> None:
        return None


class IdentityConnector(ABC):
    name = "identity"

    @abstractmethod
    async def get_user_context(self, user: User, lookback_hours: int) -> UserContext: ...

    @abstractmethod
    async def disable_user(self, user: User) -> ActionOutcome: ...

    @abstractmethod
    async def enable_user(self, user: User, data: dict[str, Any]) -> ActionOutcome: ...

    async def aclose(self) -> None:
        return None


class FirewallConnector(ABC):
    name = "firewall"

    @abstractmethod
    async def block_ip(self, ip: str, duration_seconds: int, comment: str) -> ActionOutcome: ...

    @abstractmethod
    async def unblock_ip(self, ip: str, data: dict[str, Any]) -> ActionOutcome: ...

    async def aclose(self) -> None:
        return None


class IntelProvider(ABC):
    name = "intel"
    indicator_types: frozenset[str] = frozenset({"hash", "ip"})

    def supports(self, indicator_type: str, value: str) -> bool:
        return indicator_type in self.indicator_types

    @abstractmethod
    async def lookup(self, value: str, indicator_type: str) -> ProviderResult: ...

    def result(self, value: str, indicator_type: str, **kwargs: Any) -> ProviderResult:
        return ProviderResult(provider=self.name, indicator=value, indicator_type=indicator_type, **kwargs)

    async def aclose(self) -> None:
        return None


class Summarizer(ABC):
    name = "llm"

    @abstractmethod
    async def summarize(self, facts: dict[str, Any], timeout: float) -> str: ...
