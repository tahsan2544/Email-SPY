"""Handle probe: confirm whether candidate usernames exist on public platforms.

Only public profile endpoints are used (no authentication flows, no password
reset forms). A hit means *this username is registered*, not that it belongs to
the owner of the address — every match is reported as a candidate with the
reason the handle was tested.
"""

from __future__ import annotations

import asyncio
import json
import re
from importlib import resources
from typing import Any
from urllib.parse import quote

import httpx

from emailscope.context import Context
from emailscope.models import Finding
from emailscope.modules.identity import handles_from_name

MAX_HANDLES = 8
MAX_JOBS = 72
NOTE = "Username registered — association with this address is not proven."
SOURCE_LOCAL = "derived from address"
SOURCE_NAME = "derived from observed name"


def load_sites() -> list[dict[str, Any]]:
    ref = resources.files("emailscope.data").joinpath("sites.json")
    payload = json.loads(ref.read_text(encoding="utf-8"))
    return list(payload.get("sites") or [])


def build_url(template: str, username: str) -> str:
    return template.format(username=quote(username, safe="._-"))


def classify(response: httpx.Response, site: dict[str, Any], body: str) -> str | None:
    """Return ``"exists"``, ``"missing"`` or ``None`` when undecidable."""
    status = response.status_code
    mode = site.get("exists_when")

    if mode == "json_list_nonempty":
        if status not in (200, 404):
            return None
        try:
            value = response.json()
        except ValueError:
            return None
        if isinstance(value, list):
            return "exists" if value else "missing"
        return None

    if mode == "keybase_ok":
        if status != 200:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        code = (payload.get("status") or {}).get("code")
        if code == 0:
            return "exists"
        if code:
            return "missing"
        return None

    if mode == "hn_authored":
        if status != 200:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        hits = payload.get("nbHits")
        if hits is None:
            hits = len(payload.get("hits") or [])
        return "exists" if hits else "missing"

    exists_status = set(site.get("exists_status") or [])
    missing_status = set(site.get("missing_status") or [])
    if status in exists_status:
        pattern = site.get("missing_body")
        if pattern and re.search(pattern, body, re.I):
            return "missing"
        return "exists"
    if status in missing_status:
        return "missing"
    return None


def collect_handles(
    context: Context, extra_names: list[str] | None = None
) -> list[tuple[str, str]]:
    """Ordered ``(handle, source)`` pairs to probe."""
    handles: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(handle: str, source: str) -> None:
        if handle not in seen:
            seen.add(handle)
            handles.append((handle, source))

    for handle in context.identity.handle_candidates:
        add(handle, SOURCE_LOCAL)
    for name in extra_names or []:
        for handle in handles_from_name(name):
            add(handle, SOURCE_NAME)
    return handles[:MAX_HANDLES]


async def _check(
    context: Context,
    site: dict[str, Any],
    username: str,
    source: str,
) -> dict[str, Any] | None:
    url = build_url(site["url"], username)
    headers = dict(site.get("extra_headers") or {})
    try:
        response = await context.client.get(
            url,
            headers=headers,
            retries=1,
            browser_ua=bool(site.get("browser_ua")),
            rate_limit=float(site.get("rate_limit") or context.options.rate_limit),
        )
    except httpx.HTTPError:
        return None

    body = response.text[:4000] if response.status_code < 500 else ""
    if classify(response, site, body) != "exists":
        return None

    return {
        "service": site.get("name") or site["id"],
        "site_id": site.get("id") or "",
        "username": username,
        "source": source,
        "url": build_url(site.get("profile") or site["url"], username),
        "http_status": response.status_code,
    }


async def collect(context: Context, extra_names: list[str] | None = None) -> Finding:
    title = "Candidate accounts"
    if not context.options.accounts:
        return Finding(module="accounts", title=title, status="skip", summary="Disabled.")

    handles = collect_handles(context, extra_names)
    if not handles:
        return Finding(
            module="accounts",
            title=title,
            status="info",
            summary="Local part yields no usable username.",
        )

    sites = load_sites()
    jobs = [(site, handle, source) for handle, source in handles for site in sites][:MAX_JOBS]

    semaphore = asyncio.Semaphore(8)

    async def run(site: dict[str, Any], handle: str, source: str) -> dict[str, Any] | None:
        async with semaphore:
            return await _check(context, site, handle, source)

    results = await asyncio.gather(*(run(*job) for job in jobs))

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for hit in results:
        if not hit:
            continue
        key = (hit["site_id"], hit["username"].lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)

    unique.sort(key=lambda item: (item["source"] == SOURCE_NAME, item["service"], item["username"]))

    links = [{"label": f"{h['service']} @{h['username']}", "url": h["url"]} for h in unique]
    summary = (
        f"{len(unique)} registered handle(s) across {len({h['site_id'] for h in unique})} platform(s)."
        if unique
        else "No registered handles found for the derived usernames."
    )

    return Finding(
        module="accounts",
        title=title,
        status="hit" if unique else "info",
        summary=summary,
        data={
            "note": NOTE,
            "handles_tested": [h for h, _ in handles],
            "extra_names": list(extra_names or []),
            "sites_tested": sorted({s["id"] for s in sites}),
            "matches": unique,
        },
        links=links,
    )
