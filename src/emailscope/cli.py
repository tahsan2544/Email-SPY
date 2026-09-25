"""Command-line interface for Email Spy."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.errors import MarkupError
from rich.table import Table
from rich.text import Text

from emailscope import __version__
from emailscope.context import Options
from emailscope.engine import run
from emailscope.htmlreport import to_html
from emailscope.models import Case
from emailscope.modules import identity
from emailscope.report import render, to_csv, to_json, to_markdown
from emailscope.theme import DEFAULT_THEME, THEMES, Theme, get_theme

MODULES = {
    "identity": "Offline parse: validity, provider, name and handle guesses",
    "dns": "MX, NS, SPF, DMARC, DKIM, BIMI for the domain",
    "rdap": "Registration record for the address's own domain (RDAP)",
    "ct": "Certificate transparency names for the domain (certspotter)",
    "hosts": "Hostnames observed for the domain (HackerTarget)",
    "urlscan": "Public browser scans of the domain (urlscan.io)",
    "gravatar": "Public Gravatar profile and linked verified accounts",
    "pgp": "OpenPGP key published for the address (keys.openpgp.org)",
    "github": "Public commits signed with the address (name + login)",
    "mentions": "The address itself in public code and forums (Sourcegraph, HN, Stack Exchange)",
    "social": "Mandatory accounts: Instagram, X, LinkedIn and GitHub",
    "accounts": "Candidate usernames probed against public profile endpoints",
    "mailhost": "ASN, open ports and CVEs on the mail servers (RIPE + Shodan)",
    "smtp": "RCPT TO verification against the real mail exchangers",
    "reputation": "EmailRep enrichment (needs EMAILREP_API_KEY)",
    "breaches": "Have I Been Pwned breach list (needs HIBP_API_KEY)",
    "dorks": "Ready-to-run search-engine and platform queries",
}

DEFAULT_LINK_LIMIT = 12
OPEN_LIMIT = 8
PROXY_SCHEMES = ("http://", "https://", "socks4://", "socks5://", "socks5h://", "socks4a://")


def _prog() -> str:
    """Report the name the user actually invoked, not the module path."""
    stem = Path(sys.argv[0]).stem
    return "emailspy" if stem == "emailspy" else "emailscope"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_prog(),
        description="Investigate an email address: owner identity, linked accounts, "
        "mail infrastructure and public footprint.",
        epilog="Public-source research only. Investigate addresses you are authorised to look at.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("email", nargs="*", help="email address(es) to investigate")
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="read more addresses from FILE, one per line (# starts a comment)",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="write results to FILE")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of the rich report")
    parser.add_argument(
        "--csv", action="store_true", help="emit one CSV row per module instead of the rich report"
    )
    parser.add_argument(
        "--markdown", action="store_true", help="emit Markdown instead of the rich report"
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="emit a self-contained HTML report instead of the rich report",
    )
    parser.add_argument(
        "--timeout", type=float, default=12.0, help="per-request timeout in seconds"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="minimum delay between requests to the same host",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        dest="open_links",
        help="open generated search links in the browser",
    )
    parser.add_argument(
        "--no-links", action="store_true", help="hide the search-link list in the report"
    )
    parser.add_argument(
        "--link-limit",
        type=int,
        default=DEFAULT_LINK_LIMIT,
        metavar="N",
        help="max links printed per module (0 = all)",
    )
    parser.add_argument("--quiet", action="store_true", help="hide skipped modules")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument(
        "--list-modules", action="store_true", help="list available modules and exit"
    )
    parser.add_argument(
        "--theme",
        choices=sorted(THEMES),
        default=DEFAULT_THEME,
        help="colour scheme for the report (default: %(default)s)",
    )
    parser.add_argument(
        "--only",
        metavar="MODULES",
        help="comma-separated list of modules to run, e.g. --only dns,smtp (see --list-modules)",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="route every request through a proxy, e.g. socks5h://127.0.0.1:9150 for Tor",
    )
    parser.add_argument("--list-themes", action="store_true", help="list available themes and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    for name in MODULES:
        parser.add_argument(
            f"--no-{name.replace('_', '-')}",
            action="store_true",
            dest=f"skip_{name}",
            help=f"skip the {name} module",
        )
    return parser


def _selected_modules(value: str) -> list[str]:
    """Split ``--only`` and reject anything that is not a module."""
    wanted = [part.strip().replace("-", "_") for part in value.split(",") if part.strip()]
    if not wanted:
        raise ValueError("--only needs at least one module name. See --list-modules.")
    unknown = [name for name in wanted if name not in MODULES]
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(unknown)}. See --list-modules.")
    return wanted


def _validated_proxy(value: str) -> str:
    if not value.lower().startswith(PROXY_SCHEMES):
        raise ValueError(
            f"unsupported proxy scheme in {value!r}; use http://, https://, socks5:// or socks5h://"
        )
    return value


def resolve_options(args: argparse.Namespace) -> Options:
    options = Options(
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        open_links=args.open_links,
        proxy=_validated_proxy(args.proxy) if args.proxy else None,
        env=dict(os.environ),
    )
    if args.only:
        wanted = set(_selected_modules(args.only))
        for name in MODULES:
            setattr(options, name, name in wanted)
    for name in MODULES:
        if getattr(args, f"skip_{name}", False):
            setattr(options, name, False)
    return options


def _error(console: Console, theme: Theme, message: str) -> None:
    text = Text()
    text.append("error: ", style=f"bold {theme.alert}")
    text.append(message, style=theme.ink)
    console.print(text)


def _note(console: Console, theme: Theme, label: str, message: str) -> None:
    text = Text()
    text.append(label, style=f"bold {theme.signal}")
    text.append(f"  {message}", style=theme.ink)
    console.print(text)


def _print_modules(console: Console, theme: Theme) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=f"bold {theme.signal}", no_wrap=True, width=12)
    grid.add_column(style=theme.ink, overflow="fold")
    for name, description in MODULES.items():
        grid.add_row(name, description)
    console.print(grid)


def _print_themes(console: Console, theme: Theme) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=f"bold {theme.signal}", no_wrap=True, width=10)
    grid.add_column(no_wrap=True, width=12)
    grid.add_column(style=theme.ink, no_wrap=True)
    grid.add_column(style=theme.graphite, overflow="fold")
    for name in sorted(THEMES):
        swatch = THEMES[name]
        chips = Text()
        for token in (swatch.signal, swatch.stamp, swatch.remote, swatch.alert):
            chips.append("██", style=token)
        grid.add_row(name, chips, swatch.wordmark, f"default={name == DEFAULT_THEME}")
    console.print(grid)


def _targets(args: argparse.Namespace) -> list[str]:
    """Positional addresses plus any lines from ``--batch``, de-duplicated in order."""
    raw = list(args.email or [])
    if args.batch:
        try:
            text = Path(args.batch).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(
                f"cannot read --batch file {args.batch}: {exc.strerror or exc}"
            ) from exc
        for line in text.splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                raw.append(value)
    seen: set[str] = set()
    ordered: list[str] = []
    for value in raw:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _json_payload(cases: list[Case]) -> str:
    """A single address keeps its object shape; a batch becomes an array."""
    if len(cases) == 1:
        return to_json(cases[0])
    return json.dumps([json.loads(to_json(case)) for case in cases], indent=2, ensure_ascii=False)


def _open_links(cases: list[Case], console: Console, theme: Theme, limit: int = OPEN_LIMIT) -> None:
    """Open the highest-value queries only — 8 tabs, not one per address."""
    candidates = [
        link["url"]
        for case in cases
        for finding in case.findings
        for link in finding.links
        if link["url"].startswith(("http://", "https://"))
    ]
    opened = 0
    for url in candidates[:limit]:
        try:
            if webbrowser.open(url, new=2):
                opened += 1
        except Exception:  # pragma: no cover - browser integration varies
            continue
    note = f" (of {len(candidates)} generated)" if len(candidates) > limit else ""
    console.print(Text(f"opened {opened} link(s) in the default browser{note}", style=theme.muted))


def _write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    theme = get_theme(args.theme)
    console = Console(no_color=args.no_color, stderr=False)
    err = Console(no_color=args.no_color, stderr=True)

    if args.list_themes:
        _print_themes(console, theme)
        return 0

    if args.list_modules:
        _print_modules(console, theme)
        return 0

    try:
        targets = _targets(args)
    except ValueError as exc:
        _error(err, theme, str(exc))
        return 1

    if not targets:
        _error(err, theme, "no email address given. Try: emailspy someone@example.com")
        return 1

    addresses: list[str] = []
    for raw in targets:
        parsed = identity.parse_email(raw)
        if not parsed.valid:
            _error(err, theme, f"not a valid email address: {raw}")
            return 1
        addresses.append(parsed.email)

    if args.output and args.output.endswith(".json"):
        args.json = True
    if args.output and args.output.endswith((".md", ".markdown")):
        args.markdown = True
    if args.output and args.output.endswith((".html", ".htm")):
        args.html = True
    if args.output and args.output.endswith(".csv"):
        args.csv = True

    if sum(bool(flag) for flag in (args.json, args.markdown, args.csv, args.html)) > 1:
        _error(err, theme, "use only one of --json, --markdown, --csv or --html")
        return 1

    try:
        options = resolve_options(args)
    except ValueError as exc:
        _error(err, theme, str(exc))
        return 1

    cases: list[Case] = []
    for index, email in enumerate(addresses, start=1):
        if len(addresses) > 1:
            err.print(Text(f"investigating {email} ({index}/{len(addresses)})", style=theme.muted))
        try:
            cases.append(asyncio.run(run(email, options)))
        except KeyboardInterrupt:
            err.print(Text("interrupted", style=theme.warn))
            return 130
        except Exception as exc:
            _error(err, theme, f"{email}: {type(exc).__name__}: {exc}")
            return 2

    if args.json:
        payload = _json_payload(cases)
    elif args.markdown:
        payload = "\n\n".join(to_markdown(case) for case in cases)
    elif args.csv:
        payload = to_csv(cases)
    elif args.html:
        payload = to_html(cases, proxy=options.proxy, theme=theme)
    else:
        payload = None

    if payload is not None:
        if args.output:
            _write(args.output, payload)
            _note(console, theme, "written", args.output)
        else:
            sys.stdout.write(payload if payload.endswith("\n") else payload + "\n")
        return 0

    for index, case in enumerate(cases):
        if index:
            console.print()
        try:
            render(
                case,
                console,
                theme=theme,
                show_links=not args.no_links,
                link_limit=None if args.link_limit == 0 else args.link_limit,
                quiet=args.quiet,
                proxy=options.proxy,
            )
        except MarkupError:
            console.print(to_markdown(case))

    if args.output:
        _write(args.output, _json_payload(cases))
        _note(console, theme, "written", f"{args.output} (json)")

    if args.open_links:
        _open_links(cases, console, theme)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
