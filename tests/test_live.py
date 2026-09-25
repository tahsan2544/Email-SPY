"""Opt-in tests that touch the public network.

Run with: ``EMAILSCOPE_LIVE=1 pytest -m live`` (or ``make live``).
"""

from __future__ import annotations

import asyncio
import os

import pytest

from emailscope.context import Context, Options
from emailscope.engine import run
from emailscope.http import HttpClient
from emailscope.modules import dns_intel, identity

pytestmark = pytest.mark.live

LIVE = os.environ.get("EMAILSCOPE_LIVE") == "1"
requires_network = pytest.mark.skipif(not LIVE, reason="set EMAILSCOPE_LIVE=1 to run network tests")


@requires_network
def test_offline_modules_assemble_a_case():
    options = Options(accounts=False, smtp=False, github=False, gravatar=False, dns=False)
    case = asyncio.run(run("john.doe@example.com", options))
    assert case.email == "john.doe@example.com"
    assert {f.module for f in case.findings} >= {"identity", "dorks"}
    assert all(f.status != "error" for f in case.findings)


@requires_network
def test_dns_lookup_resolves_a_real_domain():
    async def main():
        parsed = identity.parse_email("someone@gmail.com")
        async with HttpClient(timeout=15.0) as client:
            context = Context(email=parsed.email, identity=parsed, client=client, options=Options())
            return await dns_intel.collect(context)

    finding = asyncio.run(main())
    assert finding.data["domain"] == "gmail.com"
    assert finding.status in {"hit", "info"}
    assert finding.data["mx"]


@requires_network
def test_gravatar_lookup_returns_for_an_unknown_address():
    from emailscope.modules import gravatar

    async def main():
        parsed = identity.parse_email("zqxjwvunotfound991@example.org")
        async with HttpClient(timeout=15.0) as client:
            context = Context(email=parsed.email, identity=parsed, client=client, options=Options())
            return await gravatar.collect(context)

    finding = asyncio.run(main())
    assert finding.status in {"info", "hit"}
