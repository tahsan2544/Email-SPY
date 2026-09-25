"""Certificate transparency — issuances logged for the address's own domain."""

from __future__ import annotations

from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

API_URL = "https://api.certspotter.com/v1/issuances"
MAX_NAMES = 40


def in_scope(name: str, domain: str) -> bool:
    name = name.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def parse_issuances(payload: list[Any], domain: str) -> dict[str, Any]:
    """Subdomains and certificate dates from a certspotter response."""
    names: set[str] = set()
    dates: list[str] = []
    for issuance in payload:
        if not isinstance(issuance, dict):
            continue
        for name in issuance.get("dns_names") or []:
            if isinstance(name, str) and in_scope(name, domain):
                names.add(name.lower().rstrip("."))
        not_before = str(issuance.get("not_before") or "")
        if not_before:
            dates.append(not_before[:10])

    subdomains = sorted(n for n in names if n != domain.lower().rstrip("."))
    return {
        "subdomains": subdomains[:MAX_NAMES],
        "issuance_count": len(payload),
        "first_cert": min(dates) if dates else "",
        "last_cert": max(dates) if dates else "",
    }


async def collect(context: Context) -> Finding:
    if not context.options.ct:
        return Finding(
            module="ct", title="Certificate transparency", status="skip", summary="Disabled."
        )
    identity = context.identity
    if not identity.valid:
        return Finding(
            module="ct", title="Certificate transparency", status="skip", summary="Invalid address."
        )
    if identity.is_free_provider:
        return Finding(
            module="ct",
            title="Certificate transparency",
            status="skip",
            summary=(
                f"{identity.domain} is a free mail provider — its certificates describe "
                "the operator, not this address."
            ),
        )

    response = await context.client.get(
        API_URL,
        params={
            "domain": identity.domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        retries=1,
    )
    if response.status_code in {429, 503}:
        return Finding(
            module="ct",
            title="Certificate transparency",
            status="unknown",
            summary=f"certspotter returned HTTP {response.status_code}.",
        )
    if response.status_code != 200:
        return Finding(
            module="ct",
            title="Certificate transparency",
            status="unknown",
            summary=f"certspotter returned HTTP {response.status_code}.",
        )
    try:
        payload = response.json()
    except ValueError:
        return Finding(
            module="ct",
            title="Certificate transparency",
            status="unknown",
            summary="certspotter response was not JSON.",
        )
    if not isinstance(payload, list):
        message = payload.get("message") if isinstance(payload, dict) else None
        return Finding(
            module="ct",
            title="Certificate transparency",
            status="unknown",
            summary=str(message or "Unexpected certspotter response."),
        )

    data = parse_issuances(payload, identity.domain)
    if not data["issuance_count"]:
        return Finding(
            module="ct",
            title="Certificate transparency",
            status="info",
            summary=f"No certificate issuances logged for {identity.domain}.",
            data=data,
        )

    bits = [f"{data['issuance_count']} issuance(s)"]
    if data["subdomains"]:
        bits.append(f"{len(data['subdomains'])} subdomain(s)")
    if data["last_cert"]:
        bits.append(f"latest {data['last_cert']}")
    return Finding(
        module="ct",
        title="Certificate transparency",
        status="hit",
        summary=" · ".join(bits),
        data=data,
        links=[{"label": "crt.sh search", "url": f"https://crt.sh/?q=%25.{identity.domain}"}],
    )
