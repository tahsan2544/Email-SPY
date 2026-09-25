"""Search-engine deep links: hand the address to the whole open web.

Nothing is scraped here — the tool builds ready-to-open queries so the analyst
can follow the trail in their own browser (or with ``--open``).
"""

from __future__ import annotations

from urllib.parse import quote_plus

from emailscope.context import Context
from emailscope.models import Finding

ENGINES = [
    ("Google", "https://www.google.com/search?q={q}"),
    ("Bing", "https://www.bing.com/search?q={q}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("Yandex", "https://yandex.com/search/?text={q}"),
]

DIRECT = [
    ("GitHub code", "https://github.com/search?q={q}&type=code"),
    ("GitHub issues", "https://github.com/search?q={q}&type=issues"),
    ("Reddit", "https://www.reddit.com/search/?q={q}"),
    ("X / Twitter", "https://x.com/search?q={q}&f=live"),
    ("VirusTotal", "https://www.virustotal.com/gui/search/{qraw}"),
    ("grep.app", "https://grep.app/search?q={qraw}"),
    ("HIBP", "https://haveibeenpwned.com/"),
]

SITE_DORKS = [
    ("LinkedIn profiles", "site:linkedin.com/in {email}"),
    ("GitHub mentions", 'site:github.com "{email}"'),
    ("Social posts", 'site:twitter.com OR site:x.com "{email}"'),
    ("Facebook", 'site:facebook.com "{email}"'),
    ("Instagram", 'site:instagram.com "{email}"'),
    ("Reddit", 'site:reddit.com "{email}"'),
    ("Medium", 'site:medium.com "{email}"'),
    ("Stack Overflow", 'site:stackoverflow.com "{email}"'),
    ("Pastebin dumps", 'site:pastebin.com "{email}"'),
    ("Gravatar", 'site:gravatar.com "{email}"'),
    ("Web archives", 'site:archive.org "{email}"'),
    ("Spreadsheet leaks", 'filetype:csv OR filetype:xls "{email}"'),
]


def build_links(email: str, name_candidates: list[str] | None = None) -> list[dict[str, str]]:
    quoted = f'"{email}"'
    links: list[dict[str, str]] = []

    for label, template in ENGINES:
        links.append(
            {"label": f"{label}: exact address", "url": template.format(q=quote_plus(quoted))}
        )

    for label, template in SITE_DORKS:
        query = template.format(email=email)
        links.append(
            {
                "label": label,
                "url": f"https://www.google.com/search?q={quote_plus(query)}",
            }
        )

    for label, template in DIRECT:
        links.append(
            {
                "label": label,
                "url": template.format(q=quote_plus(email), qraw=quote_plus(email, safe="")),
            }
        )

    for name in (name_candidates or [])[:3]:
        query = f'site:linkedin.com/in "{name}"'
        links.append(
            {
                "label": f"LinkedIn by name: {name}",
                "url": f"https://www.google.com/search?q={quote_plus(query)}",
            }
        )
        links.append(
            {
                "label": f"Google: {name} + address",
                "url": f"https://www.google.com/search?q={quote_plus(name + ' ' + email)}",
            }
        )

    return links


async def collect(context: Context) -> Finding:
    if not context.options.dorks:
        return Finding(module="dorks", title="Web search", status="skip", summary="Disabled.")

    names = context.identity.name_candidates
    links = build_links(context.email, names)
    return Finding(
        module="dorks",
        title="Web search",
        status="info",
        summary=f"{len(links)} ready-to-run queries across search engines and platforms.",
        data={"count": len(links), "name_queries": names},
        links=links,
    )
