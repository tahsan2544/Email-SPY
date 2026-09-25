"""The five mandatory platform checks: Instagram, X, LinkedIn, GitHub, YouTube.

Every investigation reports these five accounts in their own panel — they are
the handles a reader expects to see first. The probe is the same
public-endpoint classification the candidate-account module uses; a platform
the endpoints cannot decide (bot wall, rate limit, reset connection) is
reported as ``unknown``, never guessed as absent.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote_plus

from emailscope.context import Context
from emailscope.models import Finding
from emailscope.modules import handle_probe

PLATFORM_ORDER = ("instagram", "x", "linkedin", "github", "youtube")
MAX_PLATFORM_HANDLES = 5
NOTE = handle_probe.NOTE

_SEARCHES = (
    ("Instagram", "site:instagram.com {email}"),
    ("X", "site:x.com OR site:twitter.com {email}"),
    ("LinkedIn", "site:linkedin.com/in {email}"),
    ("GitHub", 'site:github.com "{email}"'),
    ("YouTube", "site:youtube.com {email}"),
)


def _search_links(email: str) -> list[dict[str, str]]:
    """Fallback: one search query per mandatory platform, ready to open."""
    links: list[dict[str, str]] = []
    for label, template in _SEARCHES:
        query = template.format(email=email)
        links.append(
            {
                "label": f"{label} search",
                "url": f"https://www.google.com/search?q={quote_plus(query)}",
            }
        )
    return links


def _row(
    site: dict[str, Any],
    verdict: str,
    username: str = "",
    source: str = "",
    url: str = "",
) -> dict[str, str]:
    return {
        "platform": str(site.get("name") or site.get("id") or ""),
        "verdict": verdict,
        "username": username,
        "source": source,
        "url": url,
    }


async def _platform_verdict(
    context: Context, site: dict[str, Any], handles: list[tuple[str, str]]
) -> dict[str, str]:
    """First hit wins; otherwise the most informative verdict across the handles tried."""
    worst = "missing"
    for handle, source in handles:
        verdict, hit = await handle_probe.probe(context, site, handle, source)
        if verdict == "exists" and hit is not None:
            return _row(site, "exists", handle, source, str(hit["url"]))
        if verdict == "unknown":
            worst = "unknown"
    return _row(site, worst)


async def collect(context: Context, extra_names: list[str] | None = None) -> Finding:
    title = "Mandatory accounts"
    if not context.options.social:
        return Finding(module="social", title=title, status="skip", summary="Disabled.")

    core = {site["id"]: site for site in handle_probe.core_sites()}
    ordered = [core[key] for key in PLATFORM_ORDER if key in core]
    handles = handle_probe.collect_handles(context, extra_names)[:MAX_PLATFORM_HANDLES]

    if not ordered:
        return Finding(
            module="social",
            title=title,
            status="error",
            summary="No core platforms registered in sites.json.",
        )

    if not handles:
        platforms = [_row(site, "unknown") for site in ordered]
        return Finding(
            module="social",
            title=title,
            status="unknown",
            summary="No candidate usernames to probe — search links provided instead.",
            data={"note": NOTE, "handles_tested": [], "platforms": platforms},
            links=_search_links(context.email),
        )

    platforms = list(
        await asyncio.gather(*(_platform_verdict(context, site, handles) for site in ordered))
    )
    found = [row for row in platforms if row["verdict"] == "exists"]
    undecided = [row for row in platforms if row["verdict"] == "unknown"]

    if found:
        status = "hit"
        summary = (
            f"{len(found)} of {len(platforms)} platforms confirmed: "
            f"{', '.join(row['platform'] for row in found)}."
        )
    elif undecided:
        status = "unknown"
        summary = (
            f"0 of {len(platforms)} confirmed; {len(undecided)} platform(s) "
            "blocked or rate-limited."
        )
    else:
        status = "info"
        summary = (
            f"None of the {len(platforms)} platforms has a registered account "
            "for the tested handles."
        )

    links = [{"label": f"{row['platform']} @{row['username']}", "url": row["url"]} for row in found]
    if not found:
        links = _search_links(context.email)

    return Finding(
        module="social",
        title=title,
        status=status,
        summary=summary,
        data={
            "note": NOTE,
            "handles_tested": [handle for handle, _ in handles],
            "platforms": platforms,
        },
        links=links,
    )
