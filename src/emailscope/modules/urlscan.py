"""Public browser scans of the address's own domain (urlscan.io search)."""

from __future__ import annotations

from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

API_URL = "https://urlscan.io/api/v1/search/"
MAX_PAGES = 10
MAX_HOSTS = 20
TITLE = "urlscan pages"


def parse_search(payload: dict[str, Any]) -> dict[str, Any]:
    """A urlscan search reply into the scan count, sample pages and observed hosts."""
    results = payload.get("results") or []
    total = payload.get("total") or 0
    try:
        scan_count = int(total)
    except (TypeError, ValueError):
        scan_count = 0

    pages: list[dict[str, str]] = []
    hosts: list[str] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        page = item.get("page") or {}
        task = item.get("task") or {}
        if not isinstance(page, dict) or not isinstance(task, dict):
            continue
        url = str(page.get("url") or task.get("url") or "")
        if not url:
            continue
        host = str(page.get("domain") or task.get("domain") or "")
        if host and host not in hosts:
            hosts.append(host)
        pages.append(
            {
                "url": url,
                "domain": host,
                "ip": str(page.get("ip") or ""),
                "country": str(page.get("country") or ""),
                "status": str(page.get("status") or ""),
                "scanned": str(task.get("time") or "")[:10],
            }
        )
    return {"scan_count": scan_count, "pages": pages[:MAX_PAGES], "hosts": hosts[:MAX_HOSTS]}


def _unavailable(summary: str) -> Finding:
    return Finding(module="urlscan", title=TITLE, status="unknown", summary=summary)


async def collect(context: Context) -> Finding:
    if not context.options.urlscan:
        return Finding(module="urlscan", title=TITLE, status="skip", summary="Disabled.")
    identity = context.identity
    if not identity.valid:
        return Finding(module="urlscan", title=TITLE, status="skip", summary="Invalid address.")
    if identity.is_free_provider:
        return Finding(
            module="urlscan",
            title=TITLE,
            status="skip",
            summary=(
                f"{identity.domain} is a free mail provider — its scanned pages describe "
                "the operator, not this address."
            ),
        )

    response = await context.client.get(
        API_URL,
        params={"q": f"page.domain:{identity.domain}", "size": "20"},
        retries=1,
    )
    if response.status_code != 200:
        return _unavailable(f"urlscan returned HTTP {response.status_code}.")
    try:
        payload = response.json()
    except ValueError:
        return _unavailable("urlscan response was not JSON.")
    if not isinstance(payload, dict):
        return _unavailable("Unexpected urlscan response.")

    data = parse_search(payload)
    if not data["pages"]:
        return Finding(
            module="urlscan",
            title=TITLE,
            status="info",
            summary=f"No public scans recorded for {identity.domain}.",
            data=data,
        )

    bits = [f"{data['scan_count']} scan(s)"]
    if data["hosts"]:
        bits.append(f"{len(data['hosts'])} host(s) observed")
    return Finding(
        module="urlscan",
        title=TITLE,
        status="hit",
        summary=" · ".join(bits),
        data=data,
        links=[
            {
                "label": "urlscan",
                "url": f"https://urlscan.io/search/#page.domain:{identity.domain}",
            }
        ],
    )
