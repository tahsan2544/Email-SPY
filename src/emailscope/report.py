"""Rendering: rich terminal report, plus JSON, Markdown and CSV exports.

Layout is fixed; the palette and wordmark come from a :class:`~emailscope.theme.Theme`.
Three tiers carry the hierarchy instead of a grid of identical boxes:

* a **hit** gets a heavy-headed box in its status colour
* **info** and **unknown** get a thin left rule
* a **skipped** source is a single dim line — it has no content worth boxing
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from io import StringIO
from typing import Any

from rich import box as boxes
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from emailscope import __version__
from emailscope.models import Case, Finding
from emailscope.theme import STATUS_LABELS, Theme, banner_rows, get_theme

_HASH_RE = re.compile(r"^[0-9a-f]{32,}$")

_LABEL_OVERRIDES = {
    "gravatar_md5": "Gravatar MD5",
    "gravatar_sha256": "Gravatar SHA256",
    "plus_tag": "Plus tag",
    "local_part": "Local part",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "spf": "SPF",
    "dmarc": "DMARC",
    "bimi": "BIMI",
    "pwn_count": "Records",
    "http_status": "HTTP status",
    "handle_candidates": "Candidate handles",
    "user_ids": "User IDs",
    "other_addresses": "Other addresses",
    "dnssec": "DNSSEC",
    "name_candidates": "Possible names",
    "profile_url": "Profile URL",
    "avatar_url": "Avatar URL",
    "extra_names": "Observed names",
    "mx": "MX",
    "ns": "NS",
    "scan_count": "Scans",
    "code_count": "Code hits",
    "post_count": "Posts",
}

_SCALAR_KEYS = (
    "email",
    "valid",
    "local_part",
    "domain",
    "provider",
    "free_provider",
    "disposable",
    "plus_tag",
    "name_candidates",
    "handle_candidates",
    "display_name",
    "location",
    "job_title",
    "company",
    "description",
    "profile_url",
    "avatar",
    "reputation",
    "suspicious",
    "first_seen",
    "last_seen",
    "deliverable",
    "accept_all",
    "valid_mx",
    "data_breach",
    "credentials_leaked",
    "spoofable",
    "spf_strict",
    "dmarc_enforced",
    "profiles",
    "verdict",
    "names",
    "logins",
    "total_count",
    "handles_tested",
    "extra_names",
    "requires",
    "rate_limited",
    "scan_count",
    "code_count",
    "post_count",
)

_SKIP_ROW_KEYS = {
    "attempts",
    "commits",
    "repositories",
    "matches",
    "platforms",
    "breaches",
    "dkim",
    "txt",
    "mx",
    "pages",
    "code_matches",
    "post_matches",
}

# A border with a vertical rule on the left and nothing else; the blank top and
# bottom rows double as spacing between informational blocks.
LEFT_RULE = boxes.Box("\n".join(["    ", "    ", "    ", "│   ", "    ", "    ", "    ", "    "]))

_ETHICS = "public records only — authorised investigations"

# Where each module's data actually came from. Shown on the right of every
# finding heading so a reader never has to guess whose answer they are reading.
_MODULE_SOURCES = {
    "identity": "offline analysis",
    "dns": "public DNS",
    "rdap": "rdap.org",
    "ct": "certspotter",
    "hosts": "hackertarget",
    "urlscan": "urlscan.io",
    "gravatar": "gravatar.com",
    "pgp": "keys.openpgp.org",
    "github": "github.com",
    "mentions": "sourcegraph + hn + stackexchange",
    "social": "instagram+x+linkedin+github+youtube",
    "accounts": "8 profile endpoints",
    "mailhost": "ripe.net + shodan.io",
    "smtp": "mail exchangers",
    "reputation": "emailrep.io",
    "breaches": "haveibeenpwned.com",
    "dorks": "search indexes",
}


def _label_for(key: str) -> str:
    return _LABEL_OVERRIDES.get(key, key.replace("_", " ").title())


def _shorten(value: str) -> str:
    if _HASH_RE.match(value):
        return f"{value[:24]}…"
    if len(value) > 400:
        return f"{value[:400]}…"
    return value


def default_rows(data: dict[str, Any]) -> list[tuple[str, Any]]:
    """Flatten a finding's payload into printable ``label, value`` rows."""
    rows: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for key in _SCALAR_KEYS:
        if key in data and key not in seen:
            seen.add(key)
            rows.append((_label_for(key), data[key]))
    for key, value in data.items():
        if key in _SKIP_ROW_KEYS or key in seen:
            continue
        if isinstance(value, (str, int, float, bool, list)):
            rows.append((_label_for(key), value))
    return rows


def case_reference(email: str) -> str:
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:6].upper()


def summary_fields(case: Case) -> list[tuple[str, str, str]]:
    """The four facts a reader wants before opening any block.

    Returns ``label, value, tone`` triples; the tone names the palette entry
    that carries the meaning (``remote`` for third-party data, ``alert`` for a
    negative verdict, and so on) so every exporter colours them the same way.
    """
    identity = case.get("identity")
    accounts = case.get("accounts")
    social = case.get("social")
    smtp = case.get("smtp")
    github = case.get("github")

    idata = identity.data if identity else {}
    provider = idata.get("provider") or idata.get("domain") or case.email.partition("@")[2]

    fields: list[tuple[str, str, str]] = []
    if provider:
        fields.append(("PROVIDER", str(provider), "remote"))

    if smtp is None or smtp.status == "skip":
        fields.append(("MAILBOX", "not checked", "muted"))
    else:
        verdict = str(smtp.data.get("verdict") or "unknown")
        tone = {"exists": "stamp", "not_exists": "alert"}.get(verdict, "warn")
        fields.append(("MAILBOX", verdict.replace("_", " "), tone))

    matches = (accounts.data.get("matches") or []) if accounts else []
    platforms = (social.data.get("platforms") or []) if social else []
    social_hits = [row for row in platforms if row.get("verdict") == "exists"]
    handle_count = len(matches) + len(social_hits)
    fields.append(
        (
            "HANDLES",
            f"{handle_count} found" if handle_count else "none found",
            "signal" if handle_count else "muted",
        )
    )

    names: list[str] = [str(n) for n in (idata.get("name_candidates") or [])]
    for name in (github.data.get("names") or []) if github else []:
        if str(name) not in names:
            names.append(str(name))
    # "Matt" and "Matt Mullenweg" are the same person; keep the fuller form.
    names = [
        name
        for name in names
        if not any(name is not other and name.lower() in other.lower() for other in names)
    ]
    fields.append(("NAMES", ", ".join(names[:2]) if names else "—", "ink" if names else "muted"))
    return fields


class Reporter:
    def __init__(
        self,
        theme: Theme,
        console: Console,
        *,
        show_links: bool = True,
        link_limit: int | None = None,
        quiet: bool = False,
        proxy: str | None = None,
    ) -> None:
        self.theme = theme
        self.console = console
        self.show_links = show_links
        self.link_limit = link_limit
        self.quiet = quiet
        self.proxy = proxy

    # -- chrome -------------------------------------------------------------

    def _header(self, case: Case) -> None:
        theme = self.theme
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        self.console.print()
        banner = banner_rows(theme.wordmark)
        if banner and len(banner[0]) <= self.console.width:
            for row in banner:
                self.console.print(Text(row, style=f"bold {theme.signal}"))
        else:
            self.console.print(Text(theme.wordmark, style=f"bold {theme.signal}"))

        meta = Table.grid(expand=True)
        meta.add_column(no_wrap=True)
        meta.add_column(justify="right", no_wrap=True)
        meta.add_row(
            Text(f"CASE {case_reference(case.email)}", style=theme.graphite),
            Text(stamp, style=theme.graphite),
        )
        self.console.print(meta)

        local, _, domain = case.email.partition("@")
        subject = Text()
        subject.append("SUBJECT  ", style=theme.graphite)
        subject.append(local, style=f"bold {theme.ink}")
        if domain:
            subject.append("@", style=theme.graphite)
            subject.append(domain, style=theme.remote)
        self.console.print(subject)

        if self.proxy:
            egress = Text()
            egress.append("EGRESS  ", style=theme.graphite)
            egress.append(self.proxy, style=theme.ink)
            self.console.print(egress)

        self.console.rule(style=theme.steel)
        summary = self._summary_strip(case)
        if summary is not None:
            self.console.print(summary)
        self.console.print(Text(_ETHICS, style=theme.muted))
        self.console.print()

    def _summary_strip(self, case: Case) -> Table | None:
        """Render :func:`summary_fields` in the terminal's two-column grid."""
        theme = self.theme
        tones = {
            "remote": theme.remote,
            "signal": theme.signal,
            "stamp": theme.stamp,
            "alert": theme.alert,
            "warn": theme.warn,
            "graphite": theme.graphite,
            "muted": theme.muted,
            "ink": theme.ink,
        }
        table = Table.grid(expand=True, padding=(0, 3))
        fields = summary_fields(case)
        for _ in fields:
            table.add_column(justify="right", no_wrap=True, style=theme.graphite)
            table.add_column(no_wrap=True, overflow="ellipsis")
        for start in range(0, len(fields), 2):
            row: list[Any] = []
            for label, value, tone in fields[start : start + 2]:
                row.extend([label, Text(value, style=tones.get(tone, theme.ink))])
            if len(row) < 4:
                row.extend(["", ""])
            table.add_row(*row)
        return table

    def _footer(self, case: Case) -> None:
        theme = self.theme
        findings = sum(1 for f in case.findings if f.status == "hit")
        skipped = sum(1 for f in case.findings if f.status == "skip")

        self.console.print()
        self.console.rule(style=theme.steel)
        stats = Text()
        stats.append("FINDINGS ", style=theme.graphite)
        stats.append(str(findings), style=f"bold {theme.stamp if findings else theme.graphite}")
        stats.append("   SOURCES ", style=theme.graphite)
        stats.append(str(len(case.findings)), style=f"bold {theme.signal}")
        stats.append("   SKIPPED ", style=theme.graphite)
        stats.append(str(skipped), style=theme.muted)

        grid = Table.grid(expand=True)
        grid.add_column(no_wrap=True)
        grid.add_column(justify="right", no_wrap=True)
        grid.add_column(justify="right", no_wrap=True)
        grid.add_row(
            stats,
            Text(f"CASE {case_reference(case.email)}", style=theme.graphite),
            Text(f"emailspy {__version__}", style=theme.muted),
        )
        self.console.print()
        self.console.print(grid)
        self.console.print()

    # -- findings -----------------------------------------------------------

    def _source_for(self, finding: Finding) -> str:
        if finding.module == "smtp":
            domain = str(finding.data.get("domain") or "")
            if domain:
                return f"{domain} MX"
        return _MODULE_SOURCES.get(finding.module, finding.module)

    def _heading(self, finding: Finding, index: int) -> Table:
        theme = self.theme
        left = Text()
        left.append(f"{index:02d}  ", style=theme.muted)
        left.append_text(theme.chip(finding.status))
        left.append("  ")
        left.append(finding.title, style=f"bold {theme.signal}")
        grid = Table.grid(expand=True)
        grid.add_column(no_wrap=True, overflow="ellipsis")
        grid.add_column(justify="right", no_wrap=True)
        grid.add_row(left, Text(self._source_for(finding), style=theme.muted))
        return grid

    def _box_for(self, finding: Finding):
        if finding.status == "hit":
            return boxes.HEAVY_HEAD
        if finding.status == "error":
            return boxes.SQUARE
        return LEFT_RULE

    def _skip_line(self, finding: Finding, index: int) -> None:
        theme = self.theme
        grid = Table.grid(padding=(0, 2), expand=True)
        # Fixed tag width keeps every skipped title on the same column as the
        # boxed findings above; the detail column absorbs the remaining width.
        grid.add_column(width=16, no_wrap=True)
        grid.add_column(ratio=1, overflow="fold")
        grid.add_column(justify="right", no_wrap=True)

        detail = Text()
        detail.append(finding.title, style=theme.ink)
        if finding.summary:
            detail.append("  ")
            detail.append(finding.summary, style=theme.muted)
        grid.add_row(
            Text(f" {index:02d}  skipped", style=theme.muted),
            detail,
            Text(self._source_for(finding), style=theme.muted),
        )
        self.console.print(grid)

    def _panel(self, finding: Finding, index: int) -> None:
        theme = self.theme
        body: list[Any] = [self._heading(finding, index)]
        if finding.summary:
            body.append(Text(finding.summary, style=theme.summary))

        custom = self._custom(finding)
        if custom is not None:
            body.append(Text(""))
            body.append(custom)

        rows = default_rows(finding.data)
        if rows and finding.module not in {"dorks", "dns", "mailhost"}:
            body.append(Text(""))
            body.append(self._pairs(rows))

        self.console.print(
            Panel(
                Group(*body),
                box=self._box_for(finding),
                border_style=theme.status_colour(finding.status),
                padding=(0, 2),
            )
        )

    def _render_case(self, case: Case) -> None:
        self._header(case)
        for index, finding in enumerate(case.findings, start=1):
            if finding.status == "skip":
                if not self.quiet:
                    self._skip_line(finding, index)
                continue
            self._panel(finding, index)
            if self.show_links and finding.links:
                self._links(finding)
            # Left-rule blocks already pad themselves; boxed findings do not.
            if self._box_for(finding) is not LEFT_RULE:
                self.console.print()
        self._footer(case)

    # -- link list ----------------------------------------------------------

    def _links(self, finding: Finding) -> None:
        theme = self.theme
        links = finding.links if self.link_limit is None else finding.links[: self.link_limit]
        grid = Table.grid(padding=(0, 3))
        grid.add_column(style=theme.ink, no_wrap=True, max_width=34, overflow="ellipsis")
        grid.add_column(style=theme.remote, overflow="fold")
        for link in links:
            grid.add_row(link["label"], link["url"])
        self.console.print(grid)

    # -- field tables -------------------------------------------------------

    def _pairs(self, rows: list[tuple[str, Any]]) -> Table:
        theme = self.theme
        table = Table.grid(padding=(0, 2, 0, 0))
        table.add_column(style=theme.graphite, no_wrap=True)
        table.add_column(style=theme.ink, overflow="fold")
        for label, value in rows:
            if value in (None, "", [], {}):
                continue
            table.add_row(label, self._fmt(value))
        return table

    def _fmt(self, value: Any) -> Text:
        theme = self.theme
        if isinstance(value, bool):
            return Text("yes" if value else "no", style=theme.ink)
        if isinstance(value, list):
            if not value:
                return Text("—", style=theme.muted)
            return Text(", ".join(_shorten(str(v)) for v in value), style=theme.ink)
        if value in (None, ""):
            return Text("—", style=theme.muted)
        return Text(_shorten(str(value)), style=theme.ink)

    # -- per-module bodies --------------------------------------------------

    def _custom(self, finding: Finding):
        renderer = _CUSTOM_RENDERERS.get(finding.module)
        return renderer(self, finding) if renderer else None

    def _render_dns(self, finding: Finding):
        data = finding.data
        theme = self.theme
        blocks: list[Any] = []
        mx = data.get("mx") or []
        if mx:
            table = Table(
                show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
            )
            table.add_column("Priority", justify="right", style=theme.graphite)
            table.add_column("Mail exchanger", style=theme.remote)
            for host in mx:
                table.add_row(str(host.get("priority")), host.get("host", ""))
            blocks.append(table)
        blocks.append(
            self._pairs(
                [
                    ("Nameservers", ", ".join(data.get("nameservers") or [])),
                    ("IPv4", ", ".join(data.get("ipv4") or [])),
                    ("SPF", data.get("spf")),
                    ("DMARC", data.get("dmarc")),
                    ("BIMI", data.get("bimi")),
                    (
                        "DKIM selectors",
                        ", ".join(f"{k}._domainkey" for k in (data.get("dkim") or {})),
                    ),
                ]
            )
        )
        return Group(*blocks)

    def _render_github(self, finding: Finding):
        commits = finding.data.get("commits") or []
        if not commits:
            return None
        theme = self.theme
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("Repo", style=theme.remote, max_width=34, overflow="ellipsis")
        table.add_column("Date", style=theme.graphite, no_wrap=True)
        table.add_column("Commit", style=theme.ink, max_width=52, overflow="ellipsis")
        for commit in commits:
            table.add_row(
                commit.get("repository", ""),
                (commit.get("date") or "")[:10],
                commit.get("message", ""),
            )
        return table

    def _render_social(self, finding: Finding):
        platforms = finding.data.get("platforms") or []
        if not platforms:
            return None
        theme = self.theme
        verdict_colour = {
            "exists": theme.stamp,
            "missing": theme.muted,
            "unknown": theme.warn,
        }
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("Platform", style=theme.graphite, no_wrap=True)
        table.add_column("Verdict", no_wrap=True)
        table.add_column("Username", style=f"bold {theme.signal}", no_wrap=True)
        table.add_column("Profile", style=theme.remote, overflow="fold")
        for row in platforms:
            verdict = str(row.get("verdict") or "unknown")
            username = str(row.get("username") or "")
            table.add_row(
                str(row.get("platform") or ""),
                Text(verdict, style=verdict_colour.get(verdict, theme.ink)),
                f"@{username}" if username else "—",
                str(row.get("url") or "—"),
            )
        return table

    def _render_accounts(self, finding: Finding):
        matches = finding.data.get("matches") or []
        if not matches:
            return None
        theme = self.theme
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("Service", style=theme.graphite, no_wrap=True)
        table.add_column("Handle", style=f"bold {theme.signal}", no_wrap=True)
        table.add_column("Profile", style=theme.remote, overflow="fold")
        for match in matches:
            table.add_row(match["service"], f"@{match['username']}", match["url"])
        return table

    def _render_breaches(self, finding: Finding):
        breaches = finding.data.get("breaches") or []
        if not breaches:
            return None
        theme = self.theme
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("Breach", style=theme.ink, no_wrap=True)
        table.add_column("Date", style=theme.graphite, no_wrap=True)
        table.add_column("Records", justify="right", style=theme.ink)
        table.add_column("Exposed", style=theme.graphite, overflow="fold")
        for breach in breaches:
            table.add_row(
                breach.get("name", ""),
                breach.get("date", ""),
                str(breach.get("pwn_count") or ""),
                ", ".join(breach.get("data_classes") or [])[:80],
            )
        return table

    def _render_mailhost(self, finding: Finding):
        servers = finding.data.get("servers") or []
        if not servers:
            return None
        theme = self.theme
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("IP", style=theme.remote, no_wrap=True)
        table.add_column("Ports", style=theme.ink, overflow="fold")
        table.add_column("CVEs", justify="right", no_wrap=True)
        for server in servers:
            vulns = server.get("vulns") or []
            table.add_row(
                server.get("ip", ""),
                ", ".join(str(port) for port in (server.get("ports") or [])) or "—",
                Text(str(len(vulns)), style=theme.warn if vulns else theme.muted),
            )

        network_rows = [
            ("AS holder", f"{server.get('asn', '')} {server.get('holder', '')}".strip())
            for server in servers
            if server.get("asn") or server.get("holder")
        ]
        prefixes = [server["prefix"] for server in servers if server.get("prefix")]
        if prefixes:
            network_rows.append(("Announced", ", ".join(prefixes)))
        hostnames = sorted({h for server in servers for h in server.get("hostnames") or []})
        if hostnames:
            network_rows.append(("Hostnames", ", ".join(hostnames[:12])))

        blocks: list[Any] = [table]
        if network_rows:
            blocks.append(Text(""))
            blocks.append(self._pairs(network_rows))
        return Group(*blocks)

    def _render_smtp(self, finding: Finding):
        attempts = finding.data.get("attempts") or []
        if not attempts:
            return None
        theme = self.theme
        verdict_colour = {
            "exists": theme.stamp,
            "not_exists": theme.alert,
            "unknown": theme.warn,
        }
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("Mail exchanger", style=theme.remote)
        table.add_column("Verdict", no_wrap=True)
        table.add_column("Server reply", style=theme.graphite, overflow="ellipsis", max_width=64)
        for attempt in attempts:
            verdict = attempt.get("verdict", "unknown")
            table.add_row(
                attempt.get("mx", ""),
                Text(verdict.replace("_", " "), style=verdict_colour.get(verdict, theme.ink)),
                attempt.get("detail", ""),
            )
        return table

    def _render_urlscan(self, finding: Finding):
        pages = finding.data.get("pages") or []
        if not pages:
            return None
        theme = self.theme
        table = Table(
            show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
        )
        table.add_column("Scanned", style=theme.graphite, no_wrap=True)
        table.add_column("Page", style=theme.remote, max_width=44, overflow="ellipsis")
        table.add_column("IP", style=theme.ink, no_wrap=True)
        table.add_column("Geo", style=theme.ink, no_wrap=True)
        table.add_column("HTTP", justify="right", no_wrap=True)
        for page in pages:
            table.add_row(
                page.get("scanned", ""),
                page.get("url", ""),
                page.get("ip", ""),
                page.get("country", ""),
                page.get("status", ""),
            )
        return table

    def _render_mentions(self, finding: Finding):
        code = finding.data.get("code_matches") or []
        posts = finding.data.get("post_matches") or []
        if not code and not posts:
            return None
        theme = self.theme
        blocks: list[Any] = []
        if code:
            table = Table(
                show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
            )
            table.add_column("Repository", style=theme.remote, max_width=34, overflow="ellipsis")
            table.add_column("File", style=theme.ink, overflow="ellipsis")
            for match in code:
                table.add_row(match.get("repository", ""), match.get("path", ""))
            blocks.append(table)
        if posts:
            if blocks:
                blocks.append(Text(""))
            table = Table(
                show_header=True, header_style=f"bold {theme.graphite}", box=None, padding=(0, 2)
            )
            table.add_column("Source", style=theme.graphite, no_wrap=True)
            table.add_column("When", style=theme.graphite, no_wrap=True)
            table.add_column("Post", style=theme.ink, overflow="ellipsis")
            for post in posts:
                table.add_row(
                    post.get("source", ""),
                    post.get("date") or "—",
                    post.get("title", ""),
                )
            blocks.append(table)
        return Group(*blocks)


_CUSTOM_RENDERERS = {
    "dns": Reporter._render_dns,
    "mailhost": Reporter._render_mailhost,
    "github": Reporter._render_github,
    "social": Reporter._render_social,
    "accounts": Reporter._render_accounts,
    "breaches": Reporter._render_breaches,
    "smtp": Reporter._render_smtp,
    "urlscan": Reporter._render_urlscan,
    "mentions": Reporter._render_mentions,
}


def render(
    case: Case,
    console: Console | None = None,
    *,
    theme: Theme | str | None = None,
    show_links: bool = True,
    link_limit: int | None = None,
    quiet: bool = False,
    proxy: str | None = None,
) -> None:
    """Print ``case`` as a rich report on ``console``."""
    resolved = theme if isinstance(theme, Theme) else get_theme(theme)
    reporter = Reporter(
        resolved,
        console or Console(),
        show_links=show_links,
        link_limit=link_limit,
        quiet=quiet,
        proxy=proxy,
    )
    reporter._render_case(case)


def to_json(case: Case) -> str:
    payload = {
        "tool": "emailscope",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **case.to_dict(),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)


def to_csv(cases: Case | list[Case]) -> str:
    """One row per module per address — the triage view; detail stays in JSON."""
    items = [cases] if isinstance(cases, Case) else cases
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["email", "module", "status", "title", "summary", "source", "links"])
    for case in items:
        for finding in case.findings:
            writer.writerow(
                [
                    case.email,
                    finding.module,
                    finding.status,
                    finding.title,
                    finding.summary,
                    _MODULE_SOURCES.get(finding.module, finding.module),
                    " ".join(link["url"] for link in finding.links),
                ]
            )
    return buffer.getvalue()


def _md_escape(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value in (None, ""):
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def to_markdown(case: Case) -> str:
    lines = [f"# Email Spy report — `{case.email}`", ""]
    lines.append(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by emailspy {__version__}."
    )
    lines.append("")
    for finding in case.findings:
        label = STATUS_LABELS.get(finding.status, finding.status.upper())
        lines.append(f"## [{label}] {finding.title}")
        if finding.summary:
            lines.append("")
            lines.append(finding.summary)
        rows = default_rows(finding.data)
        if rows:
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("| --- | --- |")
            for name, value in rows:
                lines.append(f"| {name} | {_md_escape(value)} |")
        if finding.links:
            lines.append("")
            for link in finding.links:
                lines.append(f"- [{link['label']}]({link['url']})")
        lines.append("")
    return "\n".join(lines)
