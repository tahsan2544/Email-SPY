"""Hostnames observed for the address's own domain (HackerTarget host search)."""

from __future__ import annotations

from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

API_URL = "https://api.hackertarget.com/hostsearch/"
MAX_HOSTS = 40


def parse_hostsearch(body: str) -> dict[str, Any]:
    """``host,ip`` lines (or the service's error sentence) from a hostsearch reply."""
    text = body.strip()
    if not text:
        return {"hosts": [], "addresses": [], "error": ""}
    if text.lower().startswith("error"):
        return {"hosts": [], "addresses": [], "error": text}

    hosts: list[str] = []
    addresses: list[str] = []
    for line in text.splitlines():
        host, _, ip = line.partition(",")
        host, ip = host.strip().lower(), ip.strip()
        if not host or not ip:
            continue
        hosts.append(host)
        if ip not in addresses:
            addresses.append(ip)
    return {"hosts": hosts[:MAX_HOSTS], "addresses": addresses[:MAX_HOSTS], "error": ""}


async def collect(context: Context) -> Finding:
    if not context.options.hosts:
        return Finding(module="hosts", title="Observed hosts", status="skip", summary="Disabled.")
    identity = context.identity
    if not identity.valid:
        return Finding(
            module="hosts", title="Observed hosts", status="skip", summary="Invalid address."
        )
    if identity.is_free_provider:
        return Finding(
            module="hosts",
            title="Observed hosts",
            status="skip",
            summary=(
                f"{identity.domain} is a free mail provider — its hostnames describe "
                "the operator, not this address."
            ),
        )

    response = await context.client.get(API_URL, params={"q": identity.domain}, retries=1)
    if response.status_code != 200:
        return Finding(
            module="hosts",
            title="Observed hosts",
            status="unknown",
            summary=f"HackerTarget returned HTTP {response.status_code}.",
        )

    parsed = parse_hostsearch(response.text)
    if parsed["error"]:
        return Finding(
            module="hosts",
            title="Observed hosts",
            status="unknown",
            summary=str(parsed["error"])[:160],
        )
    if not parsed["hosts"]:
        return Finding(
            module="hosts",
            title="Observed hosts",
            status="info",
            summary=f"No hostnames returned for {identity.domain}.",
            data=parsed,
        )

    return Finding(
        module="hosts",
        title="Observed hosts",
        status="hit",
        summary=f"{len(parsed['hosts'])} hostname(s) · {len(parsed['addresses'])} address(es)",
        data=parsed,
        links=[
            {
                "label": "Host search",
                "url": f"https://api.hackertarget.com/hostsearch/?q={identity.domain}",
            }
        ],
    )
