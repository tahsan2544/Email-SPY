import json

import httpx
import pytest

from emailscope.modules.ct import parse_issuances
from emailscope.modules.dorks import build_links
from emailscope.modules.handle_probe import build_url, classify, load_sites
from emailscope.modules.hosts import parse_hostsearch
from emailscope.modules.mailhost import parse_as_overview, parse_internetdb, parse_network_info
from emailscope.modules.mentions import clean_text, parse_hn, parse_sourcegraph, parse_stackexchange
from emailscope.modules.pgp import parse_key
from emailscope.modules.rdap import parse_rdap
from emailscope.modules.urlscan import parse_search


def test_sites_json_is_well_formed():
    sites = load_sites()
    assert sites
    for site in sites:
        assert {"id", "name", "url", "profile"} <= set(site)
        assert "{username}" in site["url"]


def test_build_url_escapes_username():
    assert build_url("https://x/{username}", "a b") == "https://x/a%20b"
    assert build_url("https://x/{username}", "john.doe") == "https://x/john.doe"


def test_classify_status_pairs():
    site = {"exists_status": [200], "missing_status": [404]}
    assert classify(httpx.Response(200, text="ok"), site, "ok") == "exists"
    assert classify(httpx.Response(404, text="nope"), site, "nope") == "missing"
    assert classify(httpx.Response(403, text="blocked"), site, "blocked") is None


def test_classify_soft_404_body():
    site = {"exists_status": [200], "missing_status": [404], "missing_body": r"page not found"}
    assert classify(httpx.Response(200, text="Page not found"), site, "Page not found") == "missing"
    assert (
        classify(httpx.Response(200, text="Jane Doe, artist"), site, "Jane Doe, artist") == "exists"
    )


def test_sites_do_not_rely_on_implicit_soft_404_detection():
    for site in load_sites():
        assert "missing_body" not in site or site["missing_body"]


def test_classify_json_list_site():
    site = {"exists_when": "json_list_nonempty", "missing_status": [200]}
    assert classify(httpx.Response(200, json=[{"username": "x"}]), site, "") == "exists"
    assert classify(httpx.Response(200, json=[]), site, "") == "missing"


def test_classify_keybase_site():
    site = {"exists_when": "keybase_ok", "missing_status": [200]}
    ok = httpx.Response(200, json={"status": {"code": 0}})
    bad = httpx.Response(200, json={"status": {"code": 100}})
    assert classify(ok, site, "") == "exists"
    assert classify(bad, site, "") == "missing"


def test_classify_hn_site():
    site = {"exists_when": "hn_authored", "missing_status": [200]}
    hit = httpx.Response(200, json={"nbHits": 3, "hits": [{}]})
    miss = httpx.Response(200, json={"nbHits": 0, "hits": []})
    assert classify(hit, site, "") == "exists"
    assert classify(miss, site, "") == "missing"


def test_dork_links_encode_the_address():
    links = build_links("john.doe@example.com", ["John Doe"])
    urls = [link["url"] for link in links]
    assert any(url.startswith("https://www.google.com/search?q=") for url in urls)
    assert any("linkedin.com" in url for url in urls)
    assert all(" " not in url for url in urls)
    assert any(json.dumps(link["url"]) for link in links)


def test_dork_links_include_name_queries():
    links = build_links("john.doe@example.com", ["John Doe"])
    assert any("John+Doe" in link["url"] for link in links)


ARMORED = "\n".join(
    [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----",
        "Comment: 34BD 327B 6393 E10A 0B76  C587 0ED5 5D6D ADFD 951C",
        "Comment: Matt Mullenweg <m@mullenweg.com>",
        "Comment: Matt Mullenweg <matt@mullenweg.com>",
        "",
        "xsFNBFSYfkIBEACijEJhbWU=",
        "-----END PGP PUBLIC KEY BLOCK-----",
    ]
)


def test_parse_key_reads_fingerprint_and_user_ids():
    fingerprint, user_ids = parse_key(ARMORED)
    assert fingerprint == "34BD327B6393E10A0B76C5870ED55D6DADFD951C"
    assert user_ids == [
        "Matt Mullenweg <m@mullenweg.com>",
        "Matt Mullenweg <matt@mullenweg.com>",
    ]


def test_parse_key_ignores_body_without_comment_headers():
    assert parse_key("no comments here\njust base64") == (None, [])


def test_parse_rdap_flattens_the_fields_we_report():
    data = parse_rdap(
        {
            "ldhName": "MULLENWEG.COM",
            "status": ["clientTransferProhibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2003-03-11T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2031-03-11T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-01-02T00:00:00Z"},
            ],
            "nameservers": [{"ldhName": "NS1.X.COM"}, {"ldhName": "NS2.X.COM"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["text/vcard", [["fn", {}, "text", "Example Registrar, LLC"]]],
                },
                {"roles": ["registrant"]},
            ],
            "secureDNS": {"delegationSigned": True},
        }
    )
    assert data["domain"] == "mullenweg.com"
    assert data["registrar"] == "Example Registrar, LLC"
    assert data["registration_date"] == "2003-03-11"
    assert data["expiration_date"] == "2031-03-11"
    assert data["last_changed"] == "2024-01-02"
    assert data["nameservers"] == ["NS1.X.COM", "NS2.X.COM"]
    assert data["dnssec"] is True


def test_rdap_skips_free_mail_providers():
    import asyncio

    from emailscope.context import Context, Options
    from emailscope.modules import identity as identity_module
    from emailscope.modules import rdap

    parsed = identity_module.parse_email("someone@gmail.com")
    assert parsed.is_free_provider
    context = Context(
        email=parsed.email, identity=parsed, client=_ExplodingClient(), options=Options()
    )
    finding = asyncio.run(rdap.collect(context))
    assert finding.status == "skip"
    assert "gmail.com" in finding.summary


def test_parse_issuances_keeps_only_names_in_the_target_domain():
    payload = [
        {
            "dns_names": ["mullenweg.com", "www.mullenweg.com", "other.example.org"],
            "not_before": "2024-05-01T00:00:00Z",
        },
        {"dns_names": ["mail.mullenweg.com"], "not_before": "2023-01-09T00:00:00Z"},
    ]
    data = parse_issuances(payload, "mullenweg.com")
    assert data["subdomains"] == ["mail.mullenweg.com", "www.mullenweg.com"]
    assert data["issuance_count"] == 2
    assert data["first_cert"] == "2023-01-09"
    assert data["last_cert"] == "2024-05-01"


def test_parse_hostsearch_reads_lines_and_service_errors():
    ok = parse_hostsearch("mail.example.com,192.0.2.1\nwww.example.com,192.0.2.2\n")
    assert ok["hosts"] == ["mail.example.com", "www.example.com"]
    assert ok["addresses"] == ["192.0.2.1", "192.0.2.2"]
    assert ok["error"] == ""

    failed = parse_hostsearch("error invalid host")
    assert failed["hosts"] == []
    assert failed["error"] == "error invalid host"


def test_parse_internetdb_and_ripe_payloads():
    server = parse_internetdb(
        {
            "ports": [25, "587", 443],
            "vulns": ["CVE-2020-1"],
            "hostnames": ["mail.example.com"],
            "cpes": ["cpe:/a:x"],
        }
    )
    assert server["ports"] == [25, 443]
    assert server["vulns"] == ["CVE-2020-1"]
    assert server["hostnames"] == ["mail.example.com"]

    info = parse_network_info({"data": {"asns": ["32475"], "prefix": "184.154.192.0/19"}})
    assert info == {"asns": ["32475"], "prefix": "184.154.192.0/19"}
    assert parse_network_info({"messages": []}) == {"asns": [], "prefix": ""}

    assert parse_as_overview({"data": {"holder": "SINGLEHOP-LLC"}}) == "SINGLEHOP-LLC"
    assert parse_as_overview({"data": {}}) == ""


def test_parse_search_reads_urlscan_results():
    payload = {
        "total": 42,
        "results": [
            {
                "page": {
                    "url": "https://shop.example.com/",
                    "domain": "shop.example.com",
                    "ip": "203.0.113.9",
                    "country": "DE",
                    "status": "200",
                },
                "task": {"time": "2026-09-25T14:11:56.713Z"},
            },
            {"page": {}, "task": {}},
        ],
    }
    data = parse_search(payload)
    assert data["scan_count"] == 42
    assert data["hosts"] == ["shop.example.com"]
    assert len(data["pages"]) == 1
    assert data["pages"][0]["scanned"] == "2026-09-25"
    assert data["pages"][0]["ip"] == "203.0.113.9"


def test_urlscan_skips_free_mail_providers():
    import asyncio

    from emailscope.context import Context, Options
    from emailscope.modules import identity as identity_module
    from emailscope.modules import urlscan

    parsed = identity_module.parse_email("someone@gmail.com")
    context = Context(
        email=parsed.email, identity=parsed, client=_ExplodingClient(), options=Options()
    )
    finding = asyncio.run(urlscan.collect(context))
    assert finding.status == "skip"
    assert "gmail.com" in finding.summary


SSE_STREAM = "\n".join(
    [
        "event: filters",
        'data: [{"value":"archived:yes","label":"Include archived repos"}]',
        "",
        "event: progress",
        'data: {"done":false,"matchCount":1}',
        "",
        "event: matches",
        'data: [{"repository":"github.com/acme/tool","path":"src/mail.py",'
        '"lineMatches":[{"preview":"owner = \'user@example.com\'"}]},'
        '{"path":"orphan.py"}]',
        "",
        "event: matches",
        'data: [{"repository":"gitlab.com/acme/other","path":"cfg.txt","lineMatches":[]}]',
        "",
        "event: done",
        'data: {"done":true,"matchCount":2}',
        "",
    ]
)


def test_parse_sourcegraph_reads_only_matches_events():
    hits = parse_sourcegraph(SSE_STREAM)
    assert len(hits) == 2
    assert hits[0]["repository"] == "github.com/acme/tool"
    assert hits[0]["path"] == "src/mail.py"
    assert hits[0]["url"] == "https://sourcegraph.com/github.com/acme/tool/-/blob/src/mail.py"
    assert hits[0]["text"] == "owner = 'user@example.com'"
    assert hits[1]["url"] == "https://sourcegraph.com/gitlab.com/acme/other/-/blob/cfg.txt"
    assert hits[1]["text"] == ""


def test_parse_sourcegraph_caps_results_and_ignores_garbage():
    payload = (
        "["
        + ",".join(f'{{"repository":"github.com/acme/r{i}","path":"f{i}.py"}}' for i in range(9))
        + "]"
    )
    stream = f"event: matches\ndata: {payload}\n"
    assert len(parse_sourcegraph(stream)) == 5
    assert parse_sourcegraph("event: matches\ndata: not json\n") == []
    assert parse_sourcegraph("event: matches\ndata: {}\n") == []


def test_clean_text_strips_markup_and_collapses_whitespace():
    assert clean_text("<p>mail me &quot;now&quot;&#x2F;ok</p>") == 'mail me "now"/ok'
    assert clean_text("  spaced\n\n out ") == "spaced out"
    assert clean_text("") == ""


def test_parse_hn_prefers_titles_and_falls_back_to_comments():
    hits = parse_hn(
        {
            "hits": [
                {
                    "title": "We shipped it",
                    "url": "https://example.com/post",
                    "objectID": "11",
                    "created_at": "2024-01-02T03:04:05.000Z",
                },
                {
                    "comment_text": "email me at user@example.com",
                    "objectID": "42",
                    "created_at": "2024-05-06T00:00:00.000Z",
                },
                {"created_at": "2024-05-06T00:00:00.000Z"},
            ]
        }
    )
    assert len(hits) == 2
    assert hits[0]["title"] == "We shipped it"
    assert hits[0]["url"] == "https://example.com/post"
    assert hits[0]["date"] == "2024-01-02"
    assert hits[1]["title"] == "email me at user@example.com"
    assert hits[1]["url"] == "https://news.ycombinator.com/item?id=42"
    assert hits[1]["source"] == "hacker news"


def test_parse_stackexchange_reads_questions_with_dates():
    hits = parse_stackexchange(
        {
            "items": [
                {
                    "title": "How do I verify an address?",
                    "link": "https://stackoverflow.com/q/1",
                    "creation_date": 1700000000,
                },
                {"title": "no link"},
                {"title": "No date", "link": "https://stackoverflow.com/q/2"},
            ]
        }
    )
    assert len(hits) == 2
    assert hits[0]["date"] == "2023-11-14"
    assert hits[0]["source"] == "stack exchange"
    assert hits[1]["date"] == ""


class _ScriptedClient:
    """Replays canned responses for the mentions sources, keyed by host."""

    def __init__(self, responses: dict[str, object]):
        self.responses = responses

    async def get(self, url: str, **kwargs):
        for host, response in self.responses.items():
            if host in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected url {url}")


def _mentions_context(client):
    from emailscope.context import Context, Options
    from emailscope.modules import identity as identity_module

    parsed = identity_module.parse_email("user@example.com")
    return Context(email=parsed.email, identity=parsed, client=client, options=Options())


def test_mentions_collect_reports_hits_and_search_links():
    import asyncio

    from emailscope.modules import mentions

    client = _ScriptedClient(
        {
            "sourcegraph": httpx.Response(200, text=SSE_STREAM),
            "hn.algolia.com": httpx.Response(
                200, json={"hits": [{"title": "Hello", "objectID": "7"}]}
            ),
            "stackexchange": httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "title": "Question",
                            "link": "https://stackoverflow.com/q/9",
                            "creation_date": 1700000000,
                        }
                    ]
                },
            ),
        }
    )
    finding = asyncio.run(mentions.collect(_mentions_context(client)))
    assert finding.status == "hit"
    assert finding.data["code_count"] == 2
    assert finding.data["post_count"] == 2
    assert finding.summary == "2 code match(es) · 2 post(s)"
    labels = [link["label"] for link in finding.links]
    assert labels == ["Sourcegraph search", "Hacker News search", "Stack Overflow search"]
    assert all("user%40example.com" in link["url"] for link in finding.links)


def test_mentions_collect_is_unknown_when_every_source_fails():
    import asyncio

    from emailscope.modules import mentions

    request = httpx.Request("GET", "https://example.com")
    client = _ScriptedClient(
        {
            "sourcegraph": httpx.ConnectError("boom", request=request),
            "hn.algolia.com": httpx.ConnectError("boom", request=request),
            "stackexchange": httpx.ConnectError("boom", request=request),
        }
    )
    finding = asyncio.run(mentions.collect(_mentions_context(client)))
    assert finding.status == "unknown"
    assert "Sourcegraph" in finding.summary
    assert "Hacker News" in finding.summary
    assert "Stack Exchange" in finding.summary
    assert finding.data["errors"] and len(finding.data["errors"]) == 3


def test_every_module_is_registered_in_the_cli_and_report():
    from emailscope.cli import MODULES
    from emailscope.context import Options
    from emailscope.engine import PHASE_ONE
    from emailscope.report import _MODULE_SOURCES

    known = {name for name, _ in PHASE_ONE} | {"accounts"}
    assert set(MODULES) == known
    assert known <= set(_MODULE_SOURCES)
    for name in MODULES:
        assert hasattr(Options(), name), f"{name} has no Options switch"


class _ExplodingClient:
    """Any module that reaches for the network before checking its flag fails."""

    def __getattr__(self, name):
        raise AssertionError(f"module used the network before honouring its disable flag ({name})")


def _collectors():
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
        mentions,
        pgp,
        rdap,
        reputation,
        smtp_verify,
        urlscan,
    )

    return {
        "identity": identity.analyse_async,
        "dns": dns_intel.collect,
        "rdap": rdap.collect,
        "ct": ct.collect,
        "hosts": hosts.collect,
        "urlscan": urlscan.collect,
        "gravatar": gravatar.collect,
        "pgp": pgp.collect,
        "github": github.collect,
        "mentions": mentions.collect,
        "accounts": handle_probe.collect,
        "mailhost": mailhost.collect,
        "smtp": smtp_verify.collect,
        "reputation": reputation.collect,
        "breaches": breaches.collect,
        "dorks": dorks.collect,
    }


@pytest.mark.parametrize("module_name", sorted(_collectors()))
def test_every_module_honours_its_disable_flag(module_name):
    import asyncio

    from emailscope.cli import build_parser, resolve_options
    from emailscope.context import Context
    from emailscope.modules import identity as identity_module

    args = build_parser().parse_args(["user@example.com", f"--no-{module_name}"])
    options = resolve_options(args)
    assert getattr(options, module_name) is False

    parsed = identity_module.parse_email("user@example.com")
    context = Context(
        email=parsed.email,
        identity=parsed,
        client=_ExplodingClient(),
        options=options,
    )
    finding = asyncio.run(_collectors()[module_name](context))
    assert finding.status == "skip", f"{module_name} ran despite being disabled"
