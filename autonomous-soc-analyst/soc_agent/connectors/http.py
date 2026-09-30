"""HTTP plumbing: one place for timeouts, retries, error shaping and the egress guard."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterable

import httpx

from .base import ConnectorError

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
RequestHook = Callable[[httpx.Request], Awaitable[None]]


def create_client(
    *, request_hook: RequestHook | None, verify: bool = True, timeout: float = 10.0
) -> httpx.AsyncClient:
    """Every outbound client is created here so the egress guard cannot be bypassed.

    Redirects are never followed automatically: a redirect to an unexpected host would
    otherwise be a way to exfiltrate data or reach internal services (SSRF).
    """
    hooks: dict[str, list[Any]] = {"request": [request_hook]} if request_hook else {}
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=5.0),
        verify=verify,
        follow_redirects=False,
        event_hooks=hooks,
        headers={"User-Agent": "soc-agent/1.0"},
    )


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    header = resp.headers.get("Retry-After")
    if header:
        try:
            return min(2.0, max(0.1, float(header)))
        except ValueError:
            pass
    return min(2.0, 0.4 * (attempt + 1))


def _snippet(resp: httpx.Response, limit: int = 300) -> str:
    text = resp.text or ""
    text = " ".join(text.split())
    return text[:limit]


async def request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    service: str,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: Any = None,
    data: Any = None,
    timeout: float | None = None,
    retries: int = 0,
    expected: Iterable[int] = (200, 201, 202, 204),
    allow_404: bool = False,
) -> httpx.Response | None:
    """Send a request; returns the response, ``None`` for an allowed 404, or raises ConnectorError."""
    expected_set = set(expected)
    kwargs: dict[str, Any] = {"headers": headers, "params": params}
    if json_body is not None:
        kwargs["json"] = json_body
    if data is not None:
        kwargs["data"] = data
    if timeout is not None:
        kwargs["timeout"] = timeout
    attempt = 0
    while True:
        try:
            resp = await client.request(method, url, **kwargs)
        except ConnectorError:
            raise  # egress guard refusal: never retried
        except httpx.TimeoutException as exc:
            if attempt < retries:
                attempt += 1
                await asyncio.sleep(0.3)
                continue
            raise ConnectorError(f"{service}: request timed out") from exc
        except httpx.HTTPError as exc:
            if attempt < retries:
                attempt += 1
                await asyncio.sleep(0.3)
                continue
            raise ConnectorError(f"{service}: {type(exc).__name__}: {exc}") from exc
        if resp.status_code == 404 and allow_404:
            return None
        if resp.status_code in expected_set:
            return resp
        if resp.status_code in RETRY_STATUSES and attempt < retries:
            delay = _retry_delay(resp, attempt)
            attempt += 1
            await asyncio.sleep(delay)
            continue
        raise ConnectorError(
            f"{service}: HTTP {resp.status_code}: {_snippet(resp)}",
            status_code=resp.status_code,
            body=(resp.text or "")[:2000],
        )


def response_json(resp: httpx.Response, service: str) -> Any:
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise ConnectorError(f"{service}: response was not valid JSON") from exc
