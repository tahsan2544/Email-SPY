"""GitHub public-commit search: the address as it appears in open-source history.

Commit metadata is one of the few places where an email address is tied to a
real name and, when the address is verified on an account, to a GitHub login.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

SEARCH_URL = "https://api.github.com/search/commits"
PER_PAGE = 30


async def collect(context: Context) -> Finding:
    email = context.email
    if not context.options.github:
        return Finding(module="github", title="Code footprint", status="skip", summary="Disabled.")

    response = await context.client.get(
        SEARCH_URL,
        params={"q": f"author-email:{email}", "per_page": PER_PAGE},
        headers={"Accept": "application/vnd.github+json"},
        retries=1,
    )

    if response.status_code in (403, 429):
        return Finding(
            module="github",
            title="Code footprint",
            status="skip",
            summary="GitHub search rate limit reached — retry in a minute.",
            data={"rate_limited": True},
        )
    if response.status_code != 200:
        return Finding(
            module="github",
            title="Code footprint",
            status="error",
            summary=f"GitHub returned HTTP {response.status_code}.",
        )

    try:
        payload: dict[str, Any] = response.json()
    except ValueError:
        return Finding(
            module="github",
            title="Code footprint",
            status="error",
            summary="GitHub returned a non-JSON body.",
        )

    items = payload.get("items") or []
    total = payload.get("total_count", len(items))
    if not items:
        return Finding(
            module="github",
            title="Code footprint",
            status="info",
            summary="No public commits signed with this address.",
            data={"total_count": total, "commits": [], "names": [], "logins": []},
        )

    names: Counter[str] = Counter()
    logins: dict[str, dict[str, Any]] = {}
    repos: Counter[str] = Counter()
    commits: list[dict[str, Any]] = []
    dates: list[str] = []

    for item in items:
        commit = item.get("commit") or {}
        author = commit.get("author") or {}
        if author.get("name"):
            names[author["name"]] += 1
        if author.get("date"):
            dates.append(author["date"])

        gh_author = item.get("author") or item.get("committer") or {}
        login = gh_author.get("login")
        if login:
            logins[login] = {
                "login": login,
                "profile": gh_author.get("html_url") or f"https://github.com/{login}",
                "avatar": gh_author.get("avatar_url", ""),
            }

        repo = ((item.get("repository") or {}).get("full_name")) or ""
        if repo:
            repos[repo] += 1

        commits.append(
            {
                "message": ((commit.get("message") or "").splitlines() or [""])[0][:120],
                "repository": repo,
                "url": item.get("html_url", ""),
                "date": author.get("date", ""),
            }
        )

    display_names = [name for name, _ in names.most_common()]
    links: list[dict[str, str]] = []
    for entry in logins.values():
        links.append({"label": f"GitHub @{entry['login']}", "url": entry["profile"]})
    for repo, _ in repos.most_common(3):
        links.append({"label": repo, "url": f"https://github.com/{repo}"})
    links.append(
        {
            "label": "GitHub commit search",
            "url": f"https://github.com/search?q=author-email%3A{email}&type=commits",
        }
    )

    data: dict[str, Any] = {
        "total_count": total,
        "returned": len(items),
        "names": display_names,
        "logins": sorted(logins),
        "accounts": list(logins.values()),
        "repositories": [r for r, _ in repos.most_common(10)],
        "first_seen": min(dates) if dates else "",
        "last_seen": max(dates) if dates else "",
        "commits": commits[:10],
    }

    parts = [f"{total} public commit(s)"] + display_names[:2]
    if logins:
        parts.append(f"GitHub account: {', '.join(sorted(logins))}")

    return Finding(
        module="github",
        title="Code footprint (GitHub)",
        status="hit",
        summary=" · ".join(parts),
        data=data,
        links=links,
    )
