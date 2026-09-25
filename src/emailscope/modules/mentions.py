"""Public mentions of the address itself — code repositories and forum posts."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus

import httpx

from emailscope.context import Context
from emailscope.models import Finding

SOURCEGRAPH_URL = "https://sourcegraph.com/.api/search/stream"
HN_URL = "https://hn.algolia.com/api/v1/search"
SE_URL = "https://api.stackexchange.com/2.3/search/advanced"
TITLE = "Public mentions"
MAX_PER_SOURCE = 5
_TAG_RE = re.compile(r"<[^>]+>")


def clean_text(value: str) -> str:
    """Strip HTML and collapse whitespace — forum bodies arrive marked up."""
    return " ".join(html.unescape(_TAG_RE.sub(" ", value)).split())


def parse_sourcegraph(stream: str) -> list[dict[str, str]]:
    """SSE ``matches`` events from a Sourcegraph search stream."""
    hits: list[dict[str, str]] = []
    event = ""
    for line in stream.splitlines():
        if line.startswith("event:"):
            event = line.partition(":")[2].strip()
            continue
        if event != "matches" or not line.startswith("data:"):
            continue
        try:
            payload = json.loads(line.partition(":")[2].strip())
        except ValueError:
            continue
        if not isinstance(payload, list):
            continue
        for match in payload:
            if not isinstance(match, dict):
                continue
            repository = str(match.get("repository") or "")
            if not repository:
                continue
            path = str(match.get("path") or "")
            preview = ""
            for line_match in match.get("lineMatches") or []:
                if isinstance(line_match, dict) and line_match.get("preview"):
                    preview = str(line_match["preview"]).strip()
                    break
            hits.append(
                {
                    "source": "sourcegraph",
                    "repository": repository,
                    "path": path,
                    "url": f"https://sourcegraph.com/{repository}/-/blob/{path}"
                    if path
                    else f"https://sourcegraph.com/{repository}",
                    "text": preview[:160],
                }
            )
            if len(hits) >= MAX_PER_SOURCE:
                return hits
    return hits


def parse_hn(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Algolia HN search hits into post links."""
    hits: list[dict[str, str]] = []
    for hit in payload.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        title = clean_text(str(hit.get("title") or hit.get("comment_text") or ""))[:160]
        if not title:
            continue
        object_id = str(hit.get("objectID") or "")
        hits.append(
            {
                "source": "hacker news",
                "title": title,
                "url": str(hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}"),
                "date": str(hit.get("created_at") or "")[:10],
            }
        )
        if len(hits) >= MAX_PER_SOURCE:
            break
    return hits


def parse_stackexchange(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Stack Exchange search items into question links."""
    hits: list[dict[str, str]] = []
    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        title = clean_text(str(item.get("title") or ""))[:160]
        link = str(item.get("link") or "")
        if not title or not link:
            continue
        created = item.get("creation_date")
        date = ""
        if isinstance(created, (int, float)):
            date = datetime.fromtimestamp(created, timezone.utc).strftime("%Y-%m-%d")
        hits.append({"source": "stack exchange", "title": title, "url": link, "date": date})
        if len(hits) >= MAX_PER_SOURCE:
            break
    return hits


async def _sourcegraph(context: Context, address: str) -> tuple[list[dict[str, str]], str]:
    try:
        response = await context.client.get(
            SOURCEGRAPH_URL,
            params={"q": f'context:global "{address}" count:10', "v": "V3"},
            headers={"Accept": "text/event-stream"},
            retries=1,
        )
    except httpx.HTTPError as exc:
        return [], f"Sourcegraph: {type(exc).__name__}"
    if response.status_code != 200:
        return [], f"Sourcegraph: HTTP {response.status_code}"
    return parse_sourcegraph(response.text), ""


async def _hackernews(context: Context, address: str) -> tuple[list[dict[str, str]], str]:
    try:
        response = await context.client.get(
            HN_URL, params={"query": address, "hitsPerPage": str(MAX_PER_SOURCE)}, retries=1
        )
    except httpx.HTTPError as exc:
        return [], f"Hacker News: {type(exc).__name__}"
    if response.status_code != 200:
        return [], f"Hacker News: HTTP {response.status_code}"
    try:
        payload = response.json()
    except ValueError:
        return [], "Hacker News: response was not JSON"
    if not isinstance(payload, dict):
        return [], "Hacker News: unexpected response"
    return parse_hn(payload), ""


async def _stackexchange(context: Context, address: str) -> tuple[list[dict[str, str]], str]:
    try:
        response = await context.client.get(
            SE_URL,
            params={
                "order": "desc",
                "sort": "relevance",
                "q": address,
                "site": "stackoverflow",
                "pagesize": str(MAX_PER_SOURCE),
            },
            retries=1,
        )
    except httpx.HTTPError as exc:
        return [], f"Stack Exchange: {type(exc).__name__}"
    if response.status_code != 200:
        return [], f"Stack Exchange: HTTP {response.status_code}"
    try:
        payload = response.json()
    except ValueError:
        return [], "Stack Exchange: response was not JSON"
    if not isinstance(payload, dict):
        return [], "Stack Exchange: unexpected response"
    if payload.get("error_id"):
        return [], f"Stack Exchange: {payload.get('error_message') or 'API error'}"
    return parse_stackexchange(payload), ""


async def collect(context: Context) -> Finding:
    if not context.options.mentions:
        return Finding(module="mentions", title=TITLE, status="skip", summary="Disabled.")
    identity = context.identity
    if not identity.valid:
        return Finding(module="mentions", title=TITLE, status="skip", summary="Invalid address.")
    address = context.email

    code_hits, code_error = await _sourcegraph(context, address)
    hn_hits, hn_error = await _hackernews(context, address)
    se_hits, se_error = await _stackexchange(context, address)
    errors = [error for error in (code_error, hn_error, se_error) if error]
    post_hits = hn_hits + se_hits

    data: dict[str, Any] = {
        "code_count": len(code_hits),
        "post_count": len(post_hits),
        "code_matches": code_hits,
        "post_matches": post_hits,
    }
    if errors:
        data["errors"] = errors

    if len(errors) == 3:
        return Finding(
            module="mentions",
            title=TITLE,
            status="unknown",
            summary=" · ".join(errors),
            data=data,
        )

    quoted = quote_plus(address)
    links = [
        {
            "label": "Sourcegraph search",
            "url": f"https://sourcegraph.com/search?q=context%3Aglobal+{quoted}",
        },
        {"label": "Hacker News search", "url": f"https://hn.algolia.com/?q={quoted}"},
        {"label": "Stack Overflow search", "url": f"https://stackoverflow.com/search?q={quoted}"},
    ]

    if not code_hits and not post_hits:
        return Finding(
            module="mentions",
            title=TITLE,
            status="info",
            summary=f"No public mentions of {address} in code or discussions.",
            data=data,
            links=links,
        )

    bits = []
    if code_hits:
        bits.append(f"{len(code_hits)} code match(es)")
    if post_hits:
        bits.append(f"{len(post_hits)} post(s)")
    return Finding(
        module="mentions",
        title=TITLE,
        status="hit",
        summary=" · ".join(bits),
        data=data,
        links=links,
    )
