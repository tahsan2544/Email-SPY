import json
from io import StringIO

import pytest
from rich.console import Console

from emailscope import __version__
from emailscope.models import Case, Finding
from emailscope.modules.dns_intel import _parse_mx
from emailscope.report import render, to_csv, to_json, to_markdown


def make_case() -> Case:
    case = Case(email="john.doe@example.com")
    case.add(
        Finding(
            module="identity",
            title="Address",
            status="info",
            summary="Custom domain (example.com).",
            data={"email": "john.doe@example.com", "valid": True, "provider": None},
        )
    )
    case.add(
        Finding(
            module="accounts",
            title="Candidate accounts",
            status="hit",
            summary="1 registered handle(s).",
            data={
                "note": "Username registered — association with this address is not proven.",
                "matches": [
                    {
                        "service": "GitHub",
                        "site_id": "github",
                        "username": "johndoe",
                        "source": "derived from address",
                        "url": "https://github.com/johndoe",
                        "http_status": 200,
                    }
                ],
            },
            links=[{"label": "GitHub @johndoe", "url": "https://github.com/johndoe"}],
        )
    )
    case.add(
        Finding(
            module="dorks",
            title="Web search",
            status="info",
            summary="2 ready-to-run queries.",
            data={"count": 2},
            links=[
                {"label": "Google: exact address", "url": "https://www.google.com/search?q=secret"}
            ],
        )
    )
    case.add(
        Finding(
            module="reputation",
            title="Reputation (EmailRep)",
            status="skip",
            summary="Set EMAILREP_API_KEY to enable.",
            data={"requires": "EMAILREP_API_KEY"},
        )
    )
    return case


def test_json_export_is_valid_and_complete():
    payload = json.loads(to_json(make_case()))
    assert payload["tool"] == "emailscope"
    assert payload["email"] == "john.doe@example.com"
    assert len(payload["findings"]) == 4
    matches = payload["findings"][1]["data"]["matches"]
    assert matches[0]["username"] == "johndoe"
    assert matches[0]["url"] == "https://github.com/johndoe"


def test_markdown_export_includes_sections_and_links():
    text = to_markdown(make_case())
    assert "# Email Spy report" in text
    assert "## [INFO] Address" in text
    assert "## [FOUND] Candidate accounts" in text
    assert "https://github.com/johndoe" in text
    assert "| Field | Value |" in text


def test_render_does_not_raise():
    console = Console(file=StringIO(), force_terminal=True, width=100)
    render(make_case(), console, show_links=True)
    output = console.file.getvalue()
    assert "█████" in output, "the block wordmark should render at width 100"
    assert "CASE " in output
    assert "SUBJECT" in output
    assert "john.doe@example.com" in output
    assert "Candidate accounts" in output
    assert "github.com/johndoe" in output
    assert "google.com/search?q=secret" in output
    assert "FINDINGS" in output
    assert "9 profile endpoints" in output, "every heading carries its source"
    assert f"emailspy {__version__}" in output


def test_render_can_hide_links():
    console = Console(file=StringIO(), force_terminal=True, width=100)
    render(make_case(), console, show_links=False)
    output = console.file.getvalue()
    assert "google.com/search?q=secret" not in output
    assert "github.com/johndoe" in output


def test_header_states_the_egress_proxy():
    console = Console(file=StringIO(), width=100, color_system=None)
    render(make_case(), console, show_links=False, proxy="socks5h://127.0.0.1:9150")
    output = console.file.getvalue()
    assert "EGRESS" in output
    assert "socks5h://127.0.0.1:9150" in output
    assert output.index("EGRESS") < output.index("public records only")


def test_csv_has_one_row_per_module_and_quotes_commas():
    case = make_case()
    case.add(
        Finding(
            module="hosts",
            title="Observed hosts",
            status="info",
            summary="No hostnames returned for example.com, 0 address(es).",
            data={"hosts": [], "addresses": [], "error": ""},
        )
    )
    lines = to_csv(case).splitlines()
    assert lines[0] == "email,module,status,title,summary,source,links"
    assert len(lines) == len(case.findings) + 1
    hosts_row = next(line for line in lines if line.startswith("john.doe@example.com,hosts,"))
    assert '"No hostnames returned for example.com, 0 address(es)."' in hosts_row
    assert "hackertarget" in hosts_row


def test_urlscan_renders_a_table_instead_of_raw_dicts():
    case = Case(email="matt@wordpress.org")
    case.add(
        Finding(
            module="urlscan",
            title="urlscan pages",
            status="hit",
            summary="42 scan(s) · 1 host(s) observed",
            data={
                "scan_count": 42,
                "pages": [
                    {
                        "url": "https://shop.example.com/",
                        "domain": "shop.example.com",
                        "ip": "203.0.113.9",
                        "country": "DE",
                        "status": "200",
                        "scanned": "2026-09-25",
                    }
                ],
                "hosts": ["shop.example.com"],
            },
        )
    )
    console = Console(file=StringIO(), width=120, color_system=None)
    render(case, console, show_links=False)
    output = console.file.getvalue()
    assert "https://shop.example.com/" in output
    assert "203.0.113.9" in output
    assert "2026-09-25" in output
    assert "Scans" in output
    assert "{'url'" not in output
    assert "urlscan.io" in output


def _column(text: str, needle: str) -> int:
    position = text.index(needle)
    return position - (text.rfind("\n", 0, position) + 1)


def _plain() -> str:
    console = Console(file=StringIO(), width=100, color_system=None)
    render(make_case(), console, show_links=False)
    return console.file.getvalue()


def test_summary_strip_states_the_four_facts_before_any_block():
    output = _plain()
    for label in ("PROVIDER", "MAILBOX", "HANDLES", "NAMES"):
        assert label in output
    assert "not checked" in output, "no SMTP module in this fixture"
    assert "1 found" in output
    assert output.index("PROVIDER") < output.index("Candidate accounts")


def test_every_block_is_numbered_in_pipeline_order():
    output = _plain()
    assert "01  [ INFO  ]  Address" in output
    assert "02  [ FOUND ]  Candidate accounts" in output
    assert "04  skipped" in output
    assert _column(output, "Address") == _column(output, "Reputation"), "titles line up"


def test_footer_repeats_the_case_reference():
    output = _plain()
    assert output.count("CASE ") == 2


@pytest.mark.parametrize(
    ("records", "expected_hosts"),
    [
        (["10 mx1.example.com.", "20 mx2.example.com."], ["mx1.example.com", "mx2.example.com"]),
        (["0 ."], ["(null MX)"]),
        ([], []),
    ],
)
def test_parse_mx(records, expected_hosts):
    hosts = _parse_mx(records)
    assert [host["host"] for host in hosts] == expected_hosts


def test_parse_mx_orders_by_priority():
    hosts = _parse_mx(["30 b.example.com.", "10 a.example.com."])
    assert [host["priority"] for host in hosts] == [10, 30]
