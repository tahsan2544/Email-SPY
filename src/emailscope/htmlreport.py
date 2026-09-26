"""Self-contained HTML export — the terminal report as a file you can send.

No scripts, no webfonts, no network requests: one document that opens
anywhere, keeps the CLI report's grammar (status chips, right-aligned
source, left-rule panels) and prints cleanly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from string import Template
from typing import Any

from emailscope import __version__
from emailscope.models import Case, Finding
from emailscope.report import (
    _ETHICS,
    _MODULE_SOURCES,
    _label_for,
    case_reference,
    default_rows,
    summary_fields,
)
from emailscope.theme import STATUS_LABELS, Theme, banner_rows, get_theme

_CSS = Template(
    """
:root {
  --bg: $bg;
  --ink: $ink;
  --summary: $summary;
  --muted: $muted;
  --graphite: $graphite;
  --signal: $signal;
  --stamp: $stamp;
  --stamp-fg: $stamp_fg;
  --remote: $remote;
  --alert: $alert;
  --warn: $warn;
  --line: $line;
  --steel: $steel;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  padding: 0 1.25rem 4rem;
  color: var(--ink);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "DejaVu Sans Mono", "Liberation Mono", monospace;
  font-size: 14px;
  line-height: 1.55;
}
main, header, footer { max-width: 92ch; margin: 0 auto; }
.vh {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}
.wordmark {
  margin: 2rem 0 0.5rem;
  color: var(--signal);
  font-size: 11px;
  line-height: 1.15;
  overflow-x: auto;
}
.eyebrow { color: var(--graphite); margin: 0.2rem 0; }
.ethics { color: var(--muted); margin: 0.6rem 0 0; }
.rule { border: 0; border-top: 1px solid var(--steel); margin: 1rem 0; }
.case { margin: 2rem 0 3rem; }
.case-head { display: flex; flex-wrap: wrap; gap: 0.4rem 1.2rem; align-items: baseline; margin: 0.35rem 0 0.65rem; }
.case-head h2 { margin: 0; font-size: 1rem; font-weight: 600; }
.case-head .k { color: var(--graphite); font-weight: 400; margin-right: 0.6em; }
.case-head .local { color: var(--ink); font-weight: 700; }
.case-head .at { color: var(--graphite); }
.case-head .domain { color: var(--remote); }
.case-meta { color: var(--graphite); margin: 0.15rem 0; font-size: 0.9em; }
.summary {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.15rem 1.4rem;
  margin: 0.5rem 0 1rem;
}
.summary dt { color: var(--graphite); }
.summary dd { margin: 0; }
.t-remote { color: var(--remote); }
.t-signal { color: var(--signal); }
.t-stamp { color: var(--stamp); }
.t-alert { color: var(--alert); }
.t-warn { color: var(--warn); }
.t-muted { color: var(--muted); }
.t-ink { color: var(--ink); }
ol.findings { list-style: none; margin: 0; padding: 0; counter-reset: idx; }
.finding {
  position: relative;
  border-left: 3px solid var(--steel);
  padding: 0.4rem 0 0.4rem 3.6rem;
  margin: 1.3rem 0;
  break-inside: avoid;
}
.finding::before {
  counter-increment: idx;
  content: counter(idx, decimal-leading-zero);
  position: absolute;
  left: 0.9rem;
  top: 0.55rem;
  color: var(--graphite);
  font-size: 0.9em;
}
.finding--hit { border-left-color: var(--stamp); }
.finding--error { border-left-color: var(--alert); }
.finding--unknown { border-left-color: var(--warn); }
.finding--skip {
  border-left-color: var(--line);
  padding-top: 0.1rem;
  padding-bottom: 0.1rem;
}
.finding--skip::before { top: 0.3rem; }
.finding--skip h3 { color: var(--ink); font-size: 0.95em; font-weight: 600; }
.finding--skip .fsum { color: var(--muted); margin-top: 0.1rem; }
.finding h3 {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 0.5em;
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--signal);
}
.finding h3 .source {
  margin-left: auto;
  color: var(--muted);
  font-size: 0.85em;
  font-weight: 400;
}
.chip {
  border: 1px solid currentColor;
  padding: 0 0.35em;
  font-size: 0.78em;
  font-weight: 700;
  color: var(--graphite);
}
.chip--hit { background: var(--stamp); color: var(--stamp-fg); border-color: var(--stamp); }
.chip--info { color: var(--graphite); }
.chip--unknown { color: var(--warn); }
.chip--error { color: var(--alert); }
.chip--skip { color: var(--muted); }
.fsum { color: var(--summary); margin: 0.3rem 0 0; }
.avatar { display: block; width: 6.4rem; height: 6.4rem; border-radius: 50%; object-fit: cover; margin-top: 0.6rem; }
.rows {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: 0.1rem 1.4rem;
  margin: 0.7rem 0 0;
}
.rows dt { color: var(--graphite); }
.rows dd { margin: 0; overflow-wrap: anywhere; }
.dim { color: var(--muted); }
.tw { overflow-x: auto; margin-top: 0.8rem; }
table { border-collapse: collapse; width: 100%; table-layout: fixed; font-size: 0.92em; }
th, td { text-align: left; vertical-align: top; padding: 0.3rem 1rem 0.3rem 0; }
th {
  color: var(--graphite);
  font-weight: 600;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
td { overflow-wrap: break-word; }
td.u { overflow-wrap: anywhere; }
tbody tr + tr td { border-top: 1px solid var(--line); }
.links { list-style: none; margin: 0.8rem 0 0; padding: 0; }
.links li { overflow-wrap: anywhere; padding: 0.1rem 0; }
.links .k { color: var(--ink); margin-right: 0.8em; }
a {
  color: var(--remote);
  text-decoration: underline;
  text-decoration-thickness: 1px;
  text-underline-offset: 2px;
}
a:focus-visible { outline: 2px solid var(--signal); outline-offset: 2px; }
.case-stats {
  margin: 1.2rem 0 0;
  color: var(--graphite);
  border-top: 1px solid var(--steel);
  padding-top: 0.6rem;
}
.case-stats span { margin-right: 1.6em; }
.case-stats .n-hit { color: var(--stamp); font-weight: 700; }
.case-stats .n-src { color: var(--signal); font-weight: 700; }
.case-stats .n-skip { color: var(--muted); }
footer.doc {
  color: var(--muted);
  border-top: 1px solid var(--steel);
  padding-top: 0.8rem;
  font-size: 0.9em;
}
@media (max-width: 640px) {
  body { font-size: 13px; }
  .wordmark { font-size: 8px; }
  .finding { padding-left: 2.8rem; }
  .finding::before { left: 0.6rem; }
  .finding h3 .source { margin-left: 0; flex-basis: 100%; }
}
@media print {
  :root {
    --bg: #ffffff;
    --ink: #111111;
    --summary: #333333;
    --muted: #555555;
    --graphite: #444444;
    --signal: #0b5f5a;
    --stamp: #8a5a00;
    --stamp-fg: #ffffff;
    --remote: #0b4f9e;
    --alert: #9b1c1c;
    --warn: #7a5a00;
    --line: #cccccc;
    --steel: #999999;
  }
  body { font-size: 11pt; }
  .wordmark { font-size: 9px; }
  a { color: inherit; }
}
@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}
"""
)


def _luminance(colour: str) -> float:
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _readable(colour: str, background: str) -> str:
    """Lighten a text colour until it clears WCAG AA (4.5:1) on the page."""
    if _contrast(colour, background) >= 4.5:
        return colour
    r, g, b = (int(colour[i : i + 2], 16) for i in (1, 3, 5))
    for step in range(1, 31):
        mix = step / 30
        candidate = f"#{round(r + (255 - r) * mix):02x}{round(g + (255 - g) * mix):02x}{round(b + (255 - b) * mix):02x}"
        if _contrast(candidate, background) >= 4.5:
            return candidate
    return "#ffffff"


def _value(value: Any, cap: int | None = None) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        items = [str(item) for item in value]
        if cap is not None and len(items) > cap:
            return escape(", ".join(items[:cap]) + f" … +{len(items) - cap} more")
        return escape(", ".join(items)) or "—"
    if value in (None, ""):
        return '<span class="dim">—</span>'
    return escape(str(value))


def _table(items: list[dict[str, Any]]) -> str:
    columns: list[str] = []
    for item in items:
        for key in item:
            if key not in columns:
                columns.append(key)
    head = "".join(f'<th scope="col">{escape(_label_for(key))}</th>' for key in columns)
    body = []
    for item in items:
        cells = []
        for key in columns:
            text = str(item.get(key) or "")
            # Long URLs break anywhere; everything else keeps its words whole so
            # a narrow column cannot collapse an IP address into two characters.
            cls = ' class="u"' if "://" in text else ""
            cells.append(f"<td{cls}>{_value(item.get(key), cap=6)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return (
        f'<div class="tw"><table style="min-width:{min(len(columns) * 6, 48)}rem">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _split(data: dict[str, Any]) -> tuple[list[tuple[str, Any]], list[str]]:
    """Rows for scalars, tables for records — mirrors what the CLI panels show."""
    rows = [
        (label, value)
        for label, value in default_rows(data)
        if not (isinstance(value, list) and value and all(isinstance(v, dict) for v in value))
    ]
    tables: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            rendered = ", ".join(f"{k}: {v}" for k, v in value.items())
            if rendered:
                rows.append((_label_for(key), rendered))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            tables.append(_table(value))
    return rows, tables


def _links(links: list[dict[str, str]]) -> str:
    items = "".join(
        f'<li><span class="k">{escape(link.get("label", ""))}</span>'
        f'<a href="{escape(link.get("url", ""), quote=True)}">{escape(link.get("url", ""))}</a></li>'
        for link in links
    )
    return f'<ul class="links">{items}</ul>'


def _chip(status: str) -> str:
    label = escape(STATUS_LABELS.get(status, status.upper()))
    return f'<span class="chip chip--{escape(status)}">{label}</span>'


def _finding(finding: Finding) -> str:
    source = escape(_MODULE_SOURCES.get(finding.module, finding.module))
    title = escape(finding.title)
    summary = escape(finding.summary) if finding.summary else ""
    head = (
        f'<h3>{_chip(finding.status)}<span>{title}</span><span class="source">{source}</span></h3>'
    )
    if finding.status == "skip":
        tail = f'<p class="fsum">{summary}</p>' if summary else ""
        return f'<li class="finding finding--skip">{head}{tail}</li>'

    parts = [head]
    if summary:
        parts.append(f'<p class="fsum">{summary}</p>')
    datauri = finding.data.get("avatar_datauri")
    if isinstance(datauri, str) and datauri.startswith("data:image/"):
        parts.append(
            f'<img class="avatar" src="{escape(datauri, quote=True)}" '
            'alt="Avatar registered for this address">'
        )
    rows, tables = _split(finding.data)
    body = list(tables)
    if rows:
        body.append(
            '<dl class="rows">'
            + "".join(
                f"<dt>{escape(str(label))}</dt><dd>{_value(value)}</dd>" for label, value in rows
            )
            + "</dl>"
        )
    if body:
        parts.append("".join(body))
    if finding.links:
        parts.append(_links(finding.links))
    return f'<li class="finding finding--{escape(finding.status)}">{"".join(parts)}</li>'


def _case_block(case: Case, theme: Theme, proxy: str | None) -> str:
    reference = case_reference(case.email)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    local, _, domain = case.email.partition("@")

    subject = (
        f'<div class="case-head"><h2><span class="k">SUBJECT</span>'
        f'<span class="local">{escape(local)}</span><span class="at">@</span>'
        f'<span class="domain">{escape(domain)}</span></h2></div>'
    )
    egress = f'<p class="case-meta">EGRESS  {escape(proxy)}</p>' if proxy else ""
    summary = "".join(
        f'<dt>{escape(label)}</dt><dd class="t-{escape(tone)}">{escape(value)}</dd>'
        for label, value, tone in summary_fields(case)
    )
    findings = "".join(_finding(finding) for finding in case.findings)
    hits = sum(1 for f in case.findings if f.status == "hit")
    skipped = sum(1 for f in case.findings if f.status == "skip")
    stats = (
        f'<p class="case-stats"><span class="n-hit">FINDINGS {hits}</span>'
        f'<span class="n-src">SOURCES {len(case.findings)}</span>'
        f'<span class="n-skip">SKIPPED {skipped}</span>'
        f'<span class="k">CASE {escape(reference)}</span></p>'
    )
    return (
        f'<section class="case" id="case-{reference.lower()}" aria-label="Case {escape(reference)}">'
        f'<p class="case-meta">CASE {escape(reference)} · {stamp}</p>'
        f"{subject}"
        f"{egress}"
        f'<dl class="summary">{summary}</dl>'
        f'<ol class="findings">{findings}</ol>'
        f"{stats}"
        f"</section>"
    )


def to_html(
    cases: Case | list[Case], *, proxy: str | None = None, theme: Theme | str | None = None
) -> str:
    """Render one case — or a batch — as a single self-contained HTML document."""
    items = [cases] if isinstance(cases, Case) else cases
    resolved = theme if isinstance(theme, Theme) else get_theme(theme)
    bg = "#0e1116"
    css = _CSS.substitute(
        bg=bg,
        ink=_readable(resolved.ink, bg),
        summary=_readable(resolved.summary, bg),
        muted=_readable(resolved.muted, bg),
        graphite=_readable(resolved.graphite, bg),
        signal=_readable(resolved.signal, bg),
        stamp=_readable(resolved.stamp, bg),
        stamp_fg=resolved.stamp_fg,
        remote=_readable(resolved.remote, bg),
        alert=_readable(resolved.alert, bg),
        warn=_readable(resolved.warn, bg),
        line=resolved.steel,
        steel=resolved.steel,
    )

    banner = banner_rows(resolved.wordmark)
    if banner:
        wordmark = (
            '<pre class="wordmark" aria-hidden="true">'
            + "\n".join(escape(row) for row in banner)
            + "</pre>"
        )
    else:
        wordmark = f'<pre class="wordmark">{escape(resolved.wordmark)}</pre>'

    title = items[0].email if len(items) == 1 else f"{len(items)} addresses"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = "".join(_case_block(case, resolved, proxy) for case in items)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>EMAIL SPY — {escape(title)}</title>\n"
        f"<style>{css}</style>\n"
        "</head>\n<body>\n"
        '<header class="masthead">\n'
        f"{wordmark}\n"
        '<h1 class="vh">EMAIL SPY — public-source email investigation report</h1>\n'
        f'<p class="ethics">{escape(_ETHICS)}</p>\n'
        '</header>\n<hr class="rule">\n'
        "<main>\n"
        f"{sections}"
        "</main>\n"
        '<footer class="doc">'
        f"emailspy {escape(__version__)} · generated {escape(generated)} · public sources only"
        "</footer>\n"
        "</body>\n</html>\n"
    )
