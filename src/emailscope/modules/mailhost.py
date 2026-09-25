"""Mail-server intelligence: who runs the address's mail exchangers, and what they expose.

ASN holder comes from RIPEstat, open ports / known CVEs / hostnames from
Shodan's free InternetDB. Both are keyed by IP, so the module resolves the
domain's MX hosts itself rather than depending on the DNS finding.
"""

from __future__ import annotations

from typing import Any

from emailscope.context import Context
from emailscope.models import Finding
from emailscope.modules.dns_intel import _parse_mx, _resolve

RIPE_NETWORK_URL = "https://stat.ripe.net/data/network-info/data.json"
RIPE_AS_URL = "https://stat.ripe.net/data/as-overview/data.json"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

MAX_SERVERS = 2
MAX_MX_HOSTS = 3


def parse_internetdb(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "ports": [int(p) for p in payload.get("ports") or [] if isinstance(p, int)],
        "vulns": [str(v) for v in payload.get("vulns") or []],
        "hostnames": [str(h) for h in payload.get("hostnames") or []],
        "cpes": [str(c) for c in payload.get("cpes") or []],
    }


def parse_network_info(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return {"asns": [], "prefix": ""}
    return {
        "asns": [str(a) for a in data.get("asns") or []],
        "prefix": str(data.get("prefix") or ""),
    }


def parse_as_overview(payload: dict[str, Any]) -> str:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return ""
    return str(data.get("holder") or "")


async def _mail_addresses(domain: str) -> list[str]:
    """Addresses of the domain's mail exchangers, falling back to the domain itself."""
    mx = _parse_mx(await _resolve(domain, "MX"))
    hosts = [
        record["host"]
        for record in sorted(mx, key=lambda record: record["priority"])
        if record.get("host") not in {"", ".", "(null MX)"}
    ]

    addresses: list[str] = []
    for host in hosts[:MAX_MX_HOSTS]:
        for ip in await _resolve(host, "A"):
            if ip not in addresses:
                addresses.append(ip)
    if not addresses:
        for ip in await _resolve(domain, "A"):
            if ip not in addresses:
                addresses.append(ip)
    return addresses[:MAX_SERVERS]


async def collect(context: Context) -> Finding:
    if not context.options.mailhost:
        return Finding(module="mailhost", title="Mail servers", status="skip", summary="Disabled.")
    identity = context.identity
    if not identity.valid:
        return Finding(
            module="mailhost", title="Mail servers", status="skip", summary="Invalid address."
        )
    if identity.is_free_provider:
        return Finding(
            module="mailhost",
            title="Mail servers",
            status="skip",
            summary=(
                f"mail for {identity.domain} is handled by the provider — its servers "
                "describe the operator, not this address."
            ),
        )

    addresses = await _mail_addresses(identity.domain)
    if not addresses:
        return Finding(
            module="mailhost",
            title="Mail servers",
            status="info",
            summary="No mail exchanger addresses to inspect.",
        )

    client = context.client
    servers: list[dict[str, Any]] = []
    for ip in addresses:
        server: dict[str, Any] = {
            "ip": ip,
            "asn": "",
            "holder": "",
            "prefix": "",
            "ports": [],
            "vulns": [],
            "hostnames": [],
        }

        network = await client.get(RIPE_NETWORK_URL, params={"resource": ip}, retries=1)
        if network.status_code == 200:
            try:
                info = parse_network_info(network.json())
            except ValueError:
                info = {"asns": [], "prefix": ""}
            server["prefix"] = info["prefix"]
            if info["asns"]:
                server["asn"] = f"AS{info['asns'][0]}"
                overview = await client.get(
                    RIPE_AS_URL, params={"resource": info["asns"][0]}, retries=1
                )
                if overview.status_code == 200:
                    try:
                        server["holder"] = parse_as_overview(overview.json())
                    except ValueError:
                        server["holder"] = ""

        hostdb = await client.get(INTERNETDB_URL.format(ip=ip), retries=1)
        if hostdb.status_code == 200:
            try:
                payload = hostdb.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                server.update(parse_internetdb(payload))

        if server["asn"] or server["holder"] or server["ports"] or server["vulns"]:
            servers.append(server)

    if not servers:
        return Finding(
            module="mailhost",
            title="Mail servers",
            status="info",
            summary="No host intelligence returned for " + ", ".join(addresses) + ".",
            data={"servers": []},
        )

    first = servers[0]
    bits = [first["ip"]]
    if first["asn"]:
        bits.append(first["asn"])
    if first["holder"]:
        bits.append(first["holder"])
    if first["ports"]:
        bits.append(f"{len(first['ports'])} port(s)")
    if first["vulns"]:
        bits.append(f"{len(first['vulns'])} CVE(s)")
    if len(servers) > 1:
        bits.append(f"+{len(servers) - 1} more server(s)")

    return Finding(
        module="mailhost",
        title="Mail servers",
        status="hit",
        summary=" · ".join(bits),
        data={"servers": servers},
    )
