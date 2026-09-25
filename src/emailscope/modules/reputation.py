"""EmailRep enrichment — reputation, deliverability signals, linked profiles.

Requires an API key (``EMAILREP_API_KEY``). Without one the module reports
itself as skipped instead of burning the shared unauthenticated quota.
"""

from __future__ import annotations

from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

ENDPOINT = "https://emailrep.io/{email}"
USER_AGENT = "emailspy-osint"


async def collect(context: Context) -> Finding:
    if not context.options.reputation:
        return Finding(module="reputation", title="Reputation", status="skip", summary="Disabled.")

    key = context.options.key("EMAILREP_API_KEY")
    if not key:
        return Finding(
            module="reputation",
            title="Reputation (EmailRep)",
            status="skip",
            summary="Set EMAILREP_API_KEY to enable reputation and linked-profile enrichment.",
            data={"requires": "EMAILREP_API_KEY"},
        )

    response = await context.client.get(
        ENDPOINT.format(email=context.email),
        headers={"Key": key, "User-Agent": USER_AGENT, "Accept": "application/json"},
        retries=1,
    )

    if response.status_code == 429:
        return Finding(
            module="reputation",
            title="Reputation (EmailRep)",
            status="skip",
            summary="EmailRep rate limit reached — try again later.",
        )
    if response.status_code == 401:
        return Finding(
            module="reputation",
            title="Reputation (EmailRep)",
            status="error",
            summary="EmailRep rejected the configured API key.",
        )
    if response.status_code != 200:
        return Finding(
            module="reputation",
            title="Reputation (EmailRep)",
            status="error",
            summary=f"EmailRep returned HTTP {response.status_code}.",
        )

    try:
        payload: dict[str, Any] = response.json()
    except ValueError:
        return Finding(
            module="reputation",
            title="Reputation (EmailRep)",
            status="error",
            summary="EmailRep returned a non-JSON body.",
        )

    details = payload.get("details") or {}
    profiles = details.get("profiles") or []
    links = [
        {"label": f"{p} (EmailRep)", "url": f"https://www.google.com/search?q={p}+{context.email}"}
        for p in profiles
    ]

    data = {
        "reputation": payload.get("reputation", ""),
        "suspicious": payload.get("suspicious"),
        "references": payload.get("references"),
        "first_seen": details.get("first_seen"),
        "last_seen": details.get("last_seen"),
        "deliverable": details.get("deliverable"),
        "accept_all": details.get("accept_all"),
        "valid_mx": details.get("valid_mx"),
        "free_provider": details.get("free_provider"),
        "disposable": details.get("disposable"),
        "data_breach": details.get("data_breach"),
        "credentials_leaked": details.get("credentials_leaked"),
        "spoofable": details.get("spoofable"),
        "spf_strict": details.get("spf_strict"),
        "dmarc_enforced": details.get("dmarc_enforced"),
        "profiles": profiles,
    }

    bits = [f"reputation: {data['reputation'] or 'unknown'}"]
    if data["first_seen"]:
        bits.append(f"first seen {data['first_seen']}")
    if profiles:
        bits.append(f"{len(profiles)} linked profile(s): {', '.join(profiles)}")
    if data["data_breach"]:
        bits.append("seen in a breach")

    return Finding(
        module="reputation",
        title="Reputation (EmailRep)",
        status="hit",
        summary=" · ".join(bits),
        data=data,
        links=links,
    )
