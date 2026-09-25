"""RDAP — public registration records for the address's own domain.

Registration data for a free-mail address describes the provider's domain, not
the subject, so those runs are skipped with that reason instead of reporting
Google's expiry date as if it were theirs.
"""

from __future__ import annotations

from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

RDAP_URL = "https://rdap.org/domain/{domain}"

_EVENT_FIELDS = {
    "registration": "registration_date",
    "expiration": "expiration_date",
    "last changed": "last_changed",
}


def _vcard_name(entity: dict[str, Any]) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for entry in vcard[1]:
        if isinstance(entry, list) and entry[:1] == ["fn"] and len(entry) >= 4:
            value = entry[3]
            if isinstance(value, str):
                return value
    return ""


def parse_rdap(payload: dict[str, Any]) -> dict[str, Any]:
    """Flatten an RDAP domain response into report rows."""
    data: dict[str, Any] = {
        "domain": str(payload.get("ldhName") or "").lower(),
        "registrar": "",
        "registration_date": "",
        "expiration_date": "",
        "last_changed": "",
        "status": payload.get("status") or [],
        "nameservers": [
            str(ns.get("ldhName") or "")
            for ns in payload.get("nameservers") or []
            if isinstance(ns, dict)
        ],
    }

    for entity in payload.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in entity.get("roles") or []]
        if "registrar" in roles:
            data["registrar"] = _vcard_name(entity)
            break

    for event in payload.get("events") or []:
        if not isinstance(event, dict):
            continue
        field = _EVENT_FIELDS.get(str(event.get("eventAction") or "").lower())
        date = str(event.get("eventDate") or "")
        if field and date and not data[field]:
            data[field] = date[:10]

    secure = payload.get("secureDNS") or {}
    data["dnssec"] = bool(secure.get("delegationSigned"))
    return data


async def collect(context: Context) -> Finding:
    if not context.options.rdap:
        return Finding(
            module="rdap", title="Domain registration", status="skip", summary="Disabled."
        )
    identity = context.identity
    if not identity.valid:
        return Finding(
            module="rdap", title="Domain registration", status="skip", summary="Invalid address."
        )
    if identity.is_free_provider:
        return Finding(
            module="rdap",
            title="Domain registration",
            status="skip",
            summary=(
                f"{identity.domain} is a free mail provider — its registration data "
                "describes the operator, not this address."
            ),
        )

    response = await context.client.get(RDAP_URL.format(domain=identity.domain), retries=1)
    if response.status_code == 404:
        return Finding(
            module="rdap",
            title="Domain registration",
            status="info",
            summary=f"No RDAP record for {identity.domain}.",
        )
    if response.status_code != 200:
        return Finding(
            module="rdap",
            title="Domain registration",
            status="unknown",
            summary=f"RDAP returned HTTP {response.status_code}.",
        )
    try:
        payload = response.json()
    except ValueError:
        return Finding(
            module="rdap",
            title="Domain registration",
            status="unknown",
            summary="RDAP response was not JSON.",
        )
    if not isinstance(payload, dict):
        return Finding(
            module="rdap",
            title="Domain registration",
            status="unknown",
            summary="RDAP response was not a domain object.",
        )

    data = parse_rdap(payload)
    bits = []
    if data.get("registration_date"):
        bits.append(f"registered {data['registration_date']}")
    if data.get("expiration_date"):
        bits.append(f"expires {data['expiration_date']}")
    if data.get("registrar"):
        bits.append(str(data["registrar"]))

    links = [{"label": "RDAP record", "url": RDAP_URL.format(domain=identity.domain)}]
    return Finding(
        module="rdap",
        title="Domain registration",
        status="hit",
        summary=" · ".join(bits) or f"Registration record for {data.get('domain')}.",
        data=data,
        links=links,
    )
