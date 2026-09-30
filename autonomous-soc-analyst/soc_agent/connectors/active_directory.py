"""On-premises Active Directory over LDAPS (optional; requires the ``ldap3`` package).

Least privilege: delegate the bind account ONLY "Write userAccountControl" on the OUs
that hold standard users. Do not delegate it on admin OUs, Domain Controllers or
AdminSDHolder-protected accounts, so a compromised agent cannot lock out admins.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

from ..models import User, UserContext
from .base import ActionOutcome, ConnectorError, IdentityConnector

ACCOUNTDISABLE = 0x0002
DEFAULT_PRIVILEGED_GROUPS = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "group policy creator owners",
    "dnsadmins",
)


class ActiveDirectoryIdentity(IdentityConnector):
    name = "Active Directory"

    def __init__(
        self,
        *,
        server: str,
        bind_user: str,
        bind_password: str,
        base_dn: str,
        use_ssl: bool = True,
        privileged_groups: tuple[str, ...] = DEFAULT_PRIVILEGED_GROUPS,
        connection_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._server = server
        self._bind_user = bind_user
        self._bind_password = bind_password
        self._base_dn = base_dn
        self._use_ssl = use_ssl
        self._privileged = {g.lower() for g in privileged_groups}
        self._factory = connection_factory or self._default_connection

    def _default_connection(self) -> Any:
        try:
            import ldap3
        except ImportError as exc:  # pragma: no cover - depends on optional package
            raise ConnectorError("Active Directory support requires 'pip install ldap3'") from exc
        server = ldap3.Server(self._server, use_ssl=self._use_ssl, get_info=ldap3.NONE, connect_timeout=5)
        return ldap3.Connection(
            server, user=self._bind_user, password=self._bind_password, auto_bind=True, receive_timeout=10
        )

    def _connect(self) -> Any:
        try:
            return self._factory()
        except ConnectorError:
            raise
        except Exception as exc:  # ldap3 raises its own exception hierarchy
            raise ConnectorError(f"Active Directory bind failed: {type(exc).__name__}") from exc

    @staticmethod
    def _escape(value: str) -> str:
        """RFC 4515 filter escaping (same as ldap3.utils.conv.escape_filter_chars)."""
        out = []
        for ch in value:
            if ch in "\\*()\x00":
                out.append("\\%02x" % ord(ch))
            else:
                out.append(ch)
        return "".join(out)

    def _find(self, conn: Any, user: User) -> tuple[str, dict[str, Any]]:
        if user.sam_account:
            clause = f"(sAMAccountName={self._escape(user.sam_account)})"
        elif user.upn:
            clause = f"(userPrincipalName={self._escape(user.upn)})"
        else:
            raise ConnectorError("user has no sAMAccountName or UPN for AD lookup")
        search_filter = f"(&(objectClass=user){clause})"
        ok = conn.search(
            self._base_dn,
            search_filter,
            attributes=["userAccountControl", "memberOf", "displayName", "title", "department"],
        )
        entries = [e for e in (conn.response or []) if e.get("type") == "searchResEntry"] if ok else []
        if len(entries) != 1:
            raise ConnectorError(f"AD lookup returned {len(entries)} accounts for {user.identifier}; refusing to act")
        entry = entries[0]
        return entry["dn"], dict(entry.get("attributes") or {})

    @staticmethod
    def _first(value: Any) -> Any:
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def _context_sync(self, user: User) -> UserContext:
        conn = self._connect()
        try:
            _dn, attrs = self._find(conn, user)
        finally:
            conn.unbind()
        uac = int(self._first(attrs.get("userAccountControl")) or 0)
        groups = attrs.get("memberOf") or []
        if isinstance(groups, str):
            groups = [groups]
        names = [g.split(",", 1)[0].removeprefix("CN=").removeprefix("cn=") for g in groups]
        privileged = sorted(n for n in names if n.lower() in self._privileged)
        return UserContext(
            user=user,
            display_name=self._first(attrs.get("displayName")),
            job_title=self._first(attrs.get("title")),
            department=self._first(attrs.get("department")),
            enabled=not bool(uac & ACCOUNTDISABLE),
            on_prem_synced=True,
            privileged=bool(privileged),
            roles=[f"AD: {n}" for n in privileged],
            source=self.name,
        )

    def _set_enabled_sync(self, user: User, enabled: bool) -> ActionOutcome:
        conn = self._connect()
        try:
            dn, attrs = self._find(conn, user)
            uac = int(self._first(attrs.get("userAccountControl")) or 512)
            new = (uac & ~ACCOUNTDISABLE) if enabled else (uac | ACCOUNTDISABLE)
            if new == uac:
                state = "enabled" if enabled else "disabled"
                return ActionOutcome(detail=f"AD account already {state}", data={"dn": dn})
            try:
                from ldap3 import MODIFY_REPLACE
            except ImportError:  # pragma: no cover
                MODIFY_REPLACE = "MODIFY_REPLACE"
            ok = conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [new])]})
            if not ok:
                desc = (getattr(conn, "result", None) or {}).get("description", "unknown error")
                raise ConnectorError(f"AD modify failed: {desc}")
            verb = "re-enabled" if enabled else "disabled"
            return ActionOutcome(detail=f"AD account {verb}", data={"dn": dn})
        finally:
            conn.unbind()

    async def get_user_context(self, user: User, lookback_hours: int) -> UserContext:
        return await asyncio.to_thread(self._context_sync, user)

    async def disable_user(self, user: User) -> ActionOutcome:
        return await asyncio.to_thread(self._set_enabled_sync, user, False)

    async def enable_user(self, user: User, data: dict[str, Any]) -> ActionOutcome:
        return await asyncio.to_thread(self._set_enabled_sync, user, True)
