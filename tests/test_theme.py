from io import StringIO

from rich.console import Console

from emailscope.report import case_reference, render
from emailscope.theme import (
    CHIP_WIDTH,
    DEFAULT_THEME,
    STATUS_LABELS,
    THEMES,
    banner_rows,
    get_theme,
)
from test_report import make_case


def test_default_theme_is_spy():
    assert DEFAULT_THEME == "spy"
    assert get_theme(None).wordmark == "EMAIL SPY"
    assert get_theme("nonsense").name == "spy"


def test_classic_theme_keeps_the_old_identity():
    classic = get_theme("classic")
    assert classic.name == "classic"
    assert classic.wordmark == "EMAILSCOPE"
    assert classic.stamp == "#5FD7AF"


def test_every_status_has_a_colour_and_a_label():
    for status in ("hit", "info", "unknown", "skip", "error"):
        assert status in STATUS_LABELS
        for name, theme in THEMES.items():
            assert theme.status_colour(status).startswith("#"), f"{name}/{status}"


def test_status_colours_are_distinct():
    theme = get_theme("spy")
    colours = [theme.status_colour(s) for s in STATUS_LABELS]
    assert len(set(colours)) == len(colours)


def test_chip_is_the_same_width_for_every_status():
    theme = get_theme("spy")
    widths = {len(theme.chip(status).plain) for status in STATUS_LABELS}
    assert widths == {CHIP_WIDTH + 2}


def test_only_a_hit_chip_is_filled():
    theme = get_theme("spy")
    for status in STATUS_LABELS:
        filled = " on " in str(theme.chip(status).style)
        assert filled is (status == "hit"), status


def test_every_chip_still_lines_up():
    theme = get_theme("spy")
    widths = {len(theme.chip(status).plain) for status in STATUS_LABELS}
    assert widths == {CHIP_WIDTH + 2}


def test_banner_is_five_rows_that_fit_a_normal_terminal():
    rows = banner_rows("EMAIL SPY")
    assert rows is not None
    assert len(rows) == 5
    assert len(rows[0]) < 80
    assert len({len(row) for row in rows}) == 1


def test_banner_is_only_available_for_wordmarks_it_knows():
    assert banner_rows("EMAILSCOPE") is None
    assert banner_rows("EMAIL SPY") is not None


def test_backgrounds_only_appear_on_status_stamps():
    console = Console(file=StringIO(), force_terminal=True, width=100)
    render(make_case(), console, show_links=True)
    offending = [
        line for line in console.file.getvalue().splitlines() if "48;2" in line and "[" not in line
    ]
    assert offending == []


def test_case_reference_is_deterministic_and_scannable():
    ref = case_reference("john.doe@example.com")
    assert ref == case_reference("john.doe@example.com")
    assert ref != case_reference("jane.doe@example.com")
    assert len(ref) == 6
    assert ref.isupper() and all(c in "0123456789ABCDEF" for c in ref)


def _render(theme_name: str) -> str:
    console = Console(file=StringIO(), force_terminal=True, width=100)
    render(make_case(), console, theme=theme_name, show_links=True)
    return console.file.getvalue()


def test_spy_theme_render():
    output = _render("spy")
    assert "█████" in output
    assert "[ FOUND ]" in output


def test_narrow_terminal_falls_back_to_the_plain_wordmark():
    console = Console(file=StringIO(), force_terminal=True, width=40)
    render(make_case(), console, theme="spy")
    output = console.file.getvalue()
    assert "EMAIL SPY" in output
    assert "█" not in output


def test_classic_theme_render():
    output = _render("classic")
    assert "EMAILSCOPE" in output
    assert "EMAIL SPY" not in output


def test_skipped_sources_are_a_line_not_a_box():
    console = Console(file=StringIO(), width=100, color_system=None)
    render(make_case(), console, show_links=False)
    skip_lines = [
        line
        for line in console.file.getvalue().splitlines()
        if "skipped" in line and "Reputation" in line
    ]
    assert skip_lines, "skipped module should still be listed"
    assert all("│" not in line and "┏" not in line for line in skip_lines)


def test_quiet_hides_skipped_sources():
    console = Console(file=StringIO(), width=100, color_system=None)
    render(make_case(), console, show_links=False, quiet=True)
    assert "Reputation" not in console.file.getvalue()


def test_hits_get_a_box_and_info_gets_a_rule():
    console = Console(file=StringIO(), width=100, color_system=None)
    render(make_case(), console, show_links=False)
    output = console.file.getvalue()
    assert "┏" in output, "a hit should be boxed"
    assert "│" in output, "an info block should carry a left rule"
