from emailscope.htmlreport import _contrast, _readable, to_html
from emailscope.models import Case, Finding
from emailscope.theme import SPY


def _case(email: str = "john.doe@example.com") -> Case:
    case = Case(email=email)
    case.add(
        Finding(
            module="identity",
            title="Address",
            status="info",
            summary="Custom domain.",
            data={
                "email": email,
                "valid": True,
                "domain": email.partition("@")[2],
                "name_candidates": ["John Doe"],
            },
        )
    )
    case.add(
        Finding(
            module="mentions",
            title="Public mentions",
            status="hit",
            summary="1 code match(es)",
            data={
                "code_count": 1,
                "post_count": 0,
                "code_matches": [
                    {"repository": "github.com/acme/tool", "path": "src/mail.py", "text": "owner"}
                ],
            },
            links=[{"label": "Sourcegraph search", "url": "https://sourcegraph.com/search?q=x"}],
        )
    )
    case.add(Finding(module="smtp", title="Deliverability", status="skip", summary="Disabled."))
    return case


def test_html_is_one_self_contained_document():
    html = to_html(_case())
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html
    assert "<script" not in html
    assert '<link rel="stylesheet"' not in html and "<img" not in html
    assert "john.doe" in html and "example.com" in html
    assert "public records only" in html


def test_html_escapes_data_before_it_reaches_the_page():
    case = _case()
    case.findings[0].data["domain"] = '<script>alert("x")</script>'
    html = to_html(case)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_html_keeps_the_cli_report_grammar():
    html = to_html(_case())
    assert 'class="chip chip--hit">FOUND</span>' in html
    assert 'class="chip chip--skip">SKIPPED</span>' in html
    assert "sourcegraph + hn + stackexchange" in html
    assert '<th scope="col">Repository</th>' in html
    assert "github.com/acme/tool" in html
    assert 'href="https://sourcegraph.com/search?q=x"' in html
    assert "PROVIDER" in html and "SUBJECT" in html


def test_html_renders_a_batch_as_one_file():
    html = to_html([_case("a@example.com"), _case("b@example.org")])
    assert html.count("<!DOCTYPE html>") == 1
    assert html.count('class="case"') == 2
    assert "a@example.com" in html and "b@example.org" in html


def test_html_uses_the_selected_theme_wordmark():
    classic = to_html(_case(), theme="classic")
    assert "EMAILSCOPE" in classic
    assert to_html(_case(), theme="spy") != classic


def test_readable_text_colours_clear_wcag_aa():
    background = "#0e1116"
    for colour in (SPY.muted, SPY.graphite, SPY.ink, SPY.summary, SPY.signal, SPY.remote):
        assert _contrast(_readable(colour, background), background) >= 4.5
    assert _readable(SPY.signal, background) == SPY.signal  # already passes, untouched
