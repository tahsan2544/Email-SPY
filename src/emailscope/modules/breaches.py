"""Have I Been Pwned breach lookup — requires ``HIBP_API_KEY``."""

from __future__ import annotations

from emailscope.context import Context
from emailscope.models import Finding

ENDPOINT = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
USER_AGENT = "emailspy-osint"


async def collect(context: Context) -> Finding:
    if not context.options.breaches:
        return Finding(module="breaches", title="Breaches", status="skip", summary="Disabled.")

    key = context.options.key("HIBP_API_KEY")
    if not key:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="skip",
            summary="Set HIBP_API_KEY to check breach exposure.",
            data={"requires": "HIBP_API_KEY"},
        )

    response = await context.client.get(
        ENDPOINT.format(email=context.email),
        headers={"hibp-api-key": key, "user-agent": USER_AGENT, "Accept": "application/json"},
        params={"truncateResponse": "false"},
        retries=1,
    )

    if response.status_code == 404:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="info",
            summary="No breaches recorded for this address.",
            data={"breaches": []},
        )
    if response.status_code == 401:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="error",
            summary="HIBP rejected the configured API key.",
        )
    if response.status_code == 429:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="skip",
            summary="HIBP rate limit reached — try again later.",
        )
    if response.status_code != 200:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="error",
            summary=f"HIBP returned HTTP {response.status_code}.",
        )

    try:
        breaches = response.json()
    except ValueError:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="error",
            summary="HIBP returned a non-JSON body.",
        )

    if not isinstance(breaches, list) or not breaches:
        return Finding(
            module="breaches",
            title="Breaches (HIBP)",
            status="info",
            summary="No breaches recorded for this address.",
            data={"breaches": []},
        )

    items = [
        {
            "name": b.get("Name", ""),
            "title": b.get("Title", ""),
            "domain": b.get("Domain", ""),
            "date": b.get("BreachDate", ""),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses") or [],
        }
        for b in breaches
        if isinstance(b, dict)
    ]
    latest = max((i["date"] for i in items if i["date"]), default="")
    summary = f"{len(items)} breach(es)"
    if latest:
        summary += f", most recent {latest}"

    return Finding(
        module="breaches",
        title="Breaches (HIBP)",
        status="hit",
        summary=summary,
        data={"breaches": items},
        links=[
            {
                "label": "Have I Been Pwned",
                "url": f"https://haveibeenpwned.com/account/{context.email}",
            }
        ],
    )
