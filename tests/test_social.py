import asyncio

import httpx

from emailscope.context import Context, Options
from emailscope.modules import handle_probe, social
from emailscope.modules import identity as identity_module

IG_REAL = '<meta property="og:title" content="Jane (@jane) &#x2022; Instagram photos and videos" />'
IG_SOFT_404 = "<title>Instagram</title>"


# Replays canned responses per URL, the way mentions tests script their sources.
class _ScriptedClient:
    def __init__(self, responses: dict[str, object]):
        self.responses = responses

    async def get(self, url: str, **kwargs):
        for key, response in self.responses.items():
            if key in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected url {url}")


class _ExplodingClient:
    """Fails the test if the module reaches for the network at all."""

    def get(self, url: str, **kwargs):  # noqa: ARG002 - always raises
        raise AssertionError(f"module probed the network despite no handles: {url}")


def _context(client, email: str = "john.doe@example.com", options: Options | None = None):
    parsed = identity_module.parse_email(email)
    assert parsed.valid
    return Context(email=parsed.email, identity=parsed, client=client, options=options or Options())


def test_core_sites_are_exactly_the_five_mandatory_platforms():
    assert {site["id"] for site in handle_probe.core_sites()} == {
        "instagram",
        "x",
        "linkedin",
        "github",
        "youtube",
    }
    assert set(social.PLATFORM_ORDER) == {site["id"] for site in handle_probe.core_sites()}


def test_candidate_sites_exclude_the_mandatory_five():
    ids = {site["id"] for site in handle_probe.candidate_sites()}
    assert ids == {
        "gitlab",
        "mastodon",
        "bluesky",
        "keybase",
        "docker",
        "hn",
        "soundcloud",
        "linktree",
    }
    assert ids.isdisjoint({site["id"] for site in handle_probe.core_sites()})


def test_classify_exists_body_requires_the_marker():
    site = {"exists_status": [200], "exists_body": 'property="og:title"'}
    assert classify(site, IG_REAL) == "exists"
    assert classify(site, IG_SOFT_404) is None


def test_classify_missing_body_wins_over_exists_body():
    site = {
        "exists_status": [200],
        "exists_body": 'property="og:title"',
        "missing_body": r"<title>\s*Instagram\s*</title>",
    }
    assert classify(site, IG_SOFT_404) == "missing"
    assert classify(site, IG_REAL) == "exists"


def classify(site: dict, body: str, status: int = 200) -> str | None:
    return handle_probe.classify(httpx.Response(status, text=body), site, body)


def test_probe_honours_probe_bytes_window():
    site = {
        "id": "t",
        "name": "T",
        "url": "https://t/{username}",
        "profile": "https://t/{username}",
        "exists_status": [200],
        "exists_body": "MARKER",
        "probe_bytes": 10,
    }
    client = _ScriptedClient({"t/": httpx.Response(200, text="x" * 100 + "MARKER")})
    verdict, hit = asyncio.run(handle_probe.probe(_context(client), site, "jane", "test"))
    assert verdict == "unknown" and hit is None  # marker sits outside the window

    wide = dict(site)
    wide.pop("probe_bytes")
    verdict, hit = asyncio.run(handle_probe.probe(_context(client), wide, "jane", "test"))
    assert verdict == "exists" and hit["username"] == "jane"


def test_collect_reports_one_verdict_per_mandatory_platform():
    client = _ScriptedClient(
        {
            "instagram.com": httpx.Response(200, text=IG_REAL),
            "x.com": httpx.Response(404, text="not found"),
            "linkedin.com": httpx.Response(999, text="anti-bot interstitial"),
            "api.github.com": httpx.Response(200, json={"login": "jdoe"}),
            "youtube.com": httpx.Response(404, text="404 Not Found"),
        }
    )
    finding = asyncio.run(social.collect(_context(client)))

    assert finding.status == "hit"
    verdicts = {row["platform"]: row for row in finding.data["platforms"]}
    assert verdicts["Instagram"]["verdict"] == "exists"
    assert verdicts["Instagram"]["url"] == "https://www.instagram.com/john.doe/"
    assert verdicts["X"]["verdict"] == "missing"
    assert verdicts["LinkedIn"]["verdict"] == "unknown", "999 is a bot wall, not absence"
    assert verdicts["GitHub"]["verdict"] == "exists"
    assert verdicts["YouTube"]["verdict"] == "missing"
    assert finding.summary == "2 of 5 platforms confirmed: Instagram, GitHub."
    # Only confirmed profiles become links; search dorks are the fallback.
    assert [link["label"] for link in finding.links] == [
        "Instagram @john.doe",
        "GitHub @john.doe",
    ]


def test_collect_reports_info_when_every_platform_says_missing():
    client = _ScriptedClient(
        {
            "instagram.com": httpx.Response(200, text=IG_SOFT_404),
            "x.com": httpx.Response(404, text="nope"),
            "linkedin.com": httpx.Response(404, text="nope"),
            "api.github.com": httpx.Response(404, json={"message": "Not Found"}),
            "youtube.com": httpx.Response(404, text="404 Not Found"),
        }
    )
    finding = asyncio.run(social.collect(_context(client)))

    assert finding.status == "info"
    assert all(row["verdict"] == "missing" for row in finding.data["platforms"])
    assert finding.summary.startswith("None of the 5 platforms")
    assert all("google.com/search" in link["url"] for link in finding.links)


def test_collect_is_unknown_when_every_platform_is_blocked():
    request = httpx.Request("GET", "https://example.com")
    client = _ScriptedClient(
        {
            "instagram.com": httpx.ConnectError("boom", request=request),
            "x.com": httpx.Response(429, text="rate limited"),
            "linkedin.com": httpx.Response(999, text="blocked"),
            "api.github.com": httpx.Response(500, text="oops"),
            "youtube.com": httpx.ConnectError("boom", request=request),
        }
    )
    finding = asyncio.run(social.collect(_context(client)))

    assert finding.status == "unknown"
    assert all(row["verdict"] == "unknown" for row in finding.data["platforms"])
    assert "blocked or rate-limited" in finding.summary


def test_collect_without_handles_never_probes_and_offers_search_links():
    finding = asyncio.run(social.collect(_context(_ExplodingClient(), email="m@example.com")))

    assert finding.status == "unknown"
    assert finding.data["handles_tested"] == []
    assert all(row["verdict"] == "unknown" for row in finding.data["platforms"])
    labels = [link["label"] for link in finding.links]
    assert labels == [
        "Instagram search",
        "X search",
        "LinkedIn search",
        "GitHub search",
        "YouTube search",
    ]
    assert any("site%3Alinkedin.com" in link["url"] for link in finding.links)


def test_collect_is_skipped_when_disabled():
    client = _ExplodingClient()
    options = Options(social=False)
    finding = asyncio.run(social.collect(_context(client, options=options)))
    assert finding.status == "skip"
    assert finding.summary == "Disabled."
