"""Mail-infrastructure reconnaissance: MX, NS, SPF, DMARC, DKIM, BIMI, A."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from emailscope.context import Context
from emailscope.models import Finding

DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "sendgrid",
    "mailgun",
    "zoho",
    "protonmail",
    "cm",
    "sig1",
    "ms",
]

_QUERY_TIMEOUT = 6.0
_SEMAPHORE = asyncio.Semaphore(10)


async def _resolve(name: str, rdtype: str, timeout: float = _QUERY_TIMEOUT) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    async with _SEMAPHORE:
        try:
            answer = await resolver.resolve(name, rdtype)
        except (dns.exception.DNSException, OSError):
            return []
    return [rr.to_text() for rr in answer]


async def _txt(name: str) -> list[str]:
    return [record.strip().strip('"') for record in await _resolve(name, "TXT")]


async def _collect_dkim(domain: str, selectors: list[str]) -> dict[str, str]:
    async def one(selector: str) -> tuple[str, str]:
        values = await _txt(f"{selector}._domainkey.{domain}")
        return selector, values[0] if values else ""

    results = await asyncio.gather(*(one(s) for s in selectors))
    return {selector: value for selector, value in results if value}


def _parse_mx(records: list[str]) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    for record in records:
        parts = record.split()
        if not parts or not parts[0].isdigit():
            continue
        priority = int(parts[0])
        host = parts[1].rstrip(".") if len(parts) > 1 else ""
        if priority == 0 and not host:
            hosts.append({"host": "(null MX)", "priority": 0, "null": True})
        elif host:
            hosts.append({"host": host, "priority": priority, "null": False})
    hosts.sort(key=lambda item: item["priority"])
    return hosts


async def collect(context: Context) -> Finding:
    if not context.options.dns:
        return Finding(
            module="dns", title="Mail infrastructure", status="skip", summary="Disabled."
        )
    domain = context.identity.domain
    if not domain:
        return Finding(
            module="dns",
            title="Mail infrastructure",
            status="skip",
            summary="No domain to resolve.",
        )

    mx_raw, ns, a, aaaa, txt, dmarc, bimi, dkim_map = await asyncio.gather(
        _resolve(domain, "MX"),
        _resolve(domain, "NS"),
        _resolve(domain, "A"),
        _resolve(domain, "AAAA"),
        _txt(domain),
        _txt(f"_dmarc.{domain}"),
        _txt(f"default._bimi.{domain}"),
        _collect_dkim(domain, DKIM_SELECTORS),
    )

    mx_hosts = _parse_mx(mx_raw)
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    null_mx = any(m.get("null") for m in mx_hosts)

    data: dict[str, Any] = {
        "domain": domain,
        "mx": mx_hosts,
        "nameservers": [n.rstrip(".") for n in ns],
        "ipv4": a,
        "ipv6": aaaa,
        "spf": spf,
        "dmarc": dmarc[0] if dmarc else "",
        "dkim": {k: v[:160] for k, v in dkim_map.items()},
        "bimi": bimi[0] if bimi else "",
        "txt": txt[:20],
    }

    problems: list[str] = []
    if null_mx:
        problems.append("null MX — the domain explicitly refuses email")
    elif not mx_hosts:
        problems.append("no MX record — the domain cannot receive mail")
    if not spf:
        problems.append("no SPF record")
    if not dmarc:
        problems.append("no DMARC policy")

    if problems:
        summary = "; ".join(problems)
        status = "info"
    else:
        summary = f"{len(mx_hosts)} MX host(s), SPF and DMARC present."
        status = "hit"

    return Finding(
        module="dns",
        title="Mail infrastructure",
        status=status,
        summary=summary,
        data=data,
    )
