"""Runs the collection modules concurrently and assembles a ``Case``.

The account probe runs in a second phase so it can use the real name recovered
from public commit metadata to widen the set of candidate usernames.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from emailscope.context import Context, Options
from emailscope.http import HttpClient
from emailscope.models import Case, Finding
from emailscope.modules import (
    breaches,
    ct,
    dns_intel,
    dorks,
    github,
    gravatar,
    handle_probe,
    hosts,
    identity,
    mailhost,
    pgp,
    rdap,
    reputation,
    smtp_verify,
)

Collector = Callable[[Context], Awaitable[Finding]]

# Order matters: it is the order the report renders in.
PHASE_ONE: list[tuple[str, Collector]] = [
    ("identity", identity.analyse_async),
    ("dns", dns_intel.collect),
    ("rdap", rdap.collect),
    ("ct", ct.collect),
    ("hosts", hosts.collect),
    ("gravatar", gravatar.collect),
    ("pgp", pgp.collect),
    ("github", github.collect),
    ("mailhost", mailhost.collect),
    ("smtp", smtp_verify.collect),
    ("reputation", reputation.collect),
    ("breaches", breaches.collect),
    ("dorks", dorks.collect),
]


def _from_exception(name: str, exc: BaseException) -> Finding:
    return Finding(
        module=name,
        title=name,
        status="error",
        summary=f"{type(exc).__name__}: {exc}",
    )


async def run(email: str, options: Options | None = None) -> Case:
    """Collect everything for ``email`` and return an assembled case."""
    options = options or Options()
    parsed = identity.parse_email(email)
    case = Case(email=parsed.email)

    async with HttpClient(timeout=options.timeout, proxy=options.proxy) as client:
        context = Context(email=parsed.email, identity=parsed, client=client, options=options)

        results = await asyncio.gather(
            *(collector(context) for _, collector in PHASE_ONE), return_exceptions=True
        )

        findings: dict[str, Finding] = {}
        for (name, _), result in zip(PHASE_ONE, results, strict=True):
            findings[name] = (
                _from_exception(name, result) if isinstance(result, BaseException) else result
            )

        github_finding = findings.get("github")
        observed_names: list[str] = []
        if github_finding and github_finding.status == "hit":
            observed_names = [n for n in github_finding.data.get("names", []) if isinstance(n, str)]

        try:
            accounts = await handle_probe.collect(context, extra_names=observed_names)
        except Exception as exc:  # noqa: BLE001 - one module must not sink the report
            accounts = _from_exception("accounts", exc)

    ordered: list[Finding] = []
    for name, _ in PHASE_ONE:
        if name in findings:
            ordered.append(findings[name])
    # Render account matches straight after the code footprint that fed them.
    insert_at = next((i + 1 for i, f in enumerate(ordered) if f.module == "github"), len(ordered))
    ordered.insert(insert_at, accounts)

    for finding in ordered:
        case.add(finding)
    return case
