"""Shared HTTP plumbing: one client, sane timeouts, bounded retries, stable UA."""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from emailscope import __version__

USER_AGENT = f"emailspy/{__version__} (osint-research-client)"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

RETRY_STATUS = {429, 500, 502, 503, 504}


class HttpClient:
    """Thin wrapper around ``httpx.AsyncClient`` with retry/backoff semantics."""

    def __init__(
        self,
        timeout: float = 12.0,
        concurrency: int = 12,
        verify: bool = True,
        proxy: str | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
            follow_redirects=True,
            verify=verify,
            proxy=proxy,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        self._semaphore = asyncio.Semaphore(concurrency)
        self._locks: dict[str, asyncio.Lock] = {}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _host_lock(self, host: str) -> asyncio.Lock:
        return self._locks.setdefault(host, asyncio.Lock())

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 2,
        browser_ua: bool = False,
        rate_limit: float = 0.0,
    ) -> httpx.Response:
        """GET ``url`` returning the final response; raises ``httpx.HTTPError``."""
        request_headers = dict(headers or {})
        if browser_ua:
            request_headers.setdefault("User-Agent", BROWSER_USER_AGENT)

        last_error: httpx.HTTPError | None = None
        async with self._semaphore:
            for attempt in range(retries + 1):
                host = httpx.URL(url).host or ""
                if rate_limit:
                    async with self._host_lock(host):
                        await asyncio.sleep(rate_limit)
                try:
                    response = await self._client.get(url, params=params, headers=request_headers)
                except httpx.HTTPError as exc:
                    last_error = exc
                    await asyncio.sleep(0.4 * (2**attempt) + random.random() * 0.2)
                    continue
                if response.status_code in RETRY_STATUS and attempt < retries:
                    await asyncio.sleep(0.6 * (2**attempt) + random.random() * 0.3)
                    continue
                return response
        assert last_error is not None
        raise last_error

    async def post(
        self,
        url: str,
        *,
        content: bytes | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 1,
    ) -> httpx.Response:
        request_headers = dict(headers or {})
        last_error: httpx.HTTPError | None = None
        async with self._semaphore:
            for attempt in range(retries + 1):
                try:
                    response = await self._client.post(
                        url, content=content, data=data, headers=request_headers
                    )
                except httpx.HTTPError as exc:
                    last_error = exc
                    await asyncio.sleep(0.4 * (2**attempt))
                    continue
                if response.status_code in RETRY_STATUS and attempt < retries:
                    await asyncio.sleep(0.6 * (2**attempt))
                    continue
                return response
        assert last_error is not None
        raise last_error
