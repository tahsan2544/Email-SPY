"""Visual themes for the terminal report.

A theme is a palette plus the wordmark. It carries no layout: layout is shared
so that both themes stay honest about what a colour means.

Palette rationale for ``spy`` — the default. The tool reads intercepts and
dossiers, so the colours come from that material rather than from a generic
terminal scheme:

``signal``   teal, the analyst's own voice: wordmark, section titles, handles
             we derived
``stamp``    telegraph amber, reserved for a confirmed hit — the only filled
             background anywhere in the report
``remote``   sky, everything owned by a third party: URLs, hosts, accounts
``alert``    red, failure and negative SMTP verdicts
``warn``     yellow, "we could not tell"
``graphite`` field labels, timestamps, the neutral "we looked and this is it"

Only a ``hit`` gets a stamp with a background; every other status is outlined
text in its own colour, so the filled amber block is the one thing the eye
lands on.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text

STATUS_LABELS: dict[str, str] = {
    "hit": "FOUND",
    "info": "INFO",
    "unknown": "UNKNOWN",
    "skip": "SKIPPED",
    "error": "ERROR",
}

CHIP_WIDTH = 7


@dataclass(frozen=True)
class Theme:
    name: str
    wordmark: str
    signal: str
    stamp: str
    remote: str
    alert: str
    warn: str
    graphite: str
    ink: str
    summary: str
    steel: str
    muted: str
    stamp_fg: str

    def status_colour(self, status: str) -> str:
        return {
            "hit": self.stamp,
            "info": self.graphite,
            "unknown": self.warn,
            "skip": self.muted,
            "error": self.alert,
        }.get(status, self.graphite)

    def chip(self, status: str) -> Text:
        """The status stamp: identical width everywhere, filled only for a hit."""
        label = STATUS_LABELS.get(status, status.upper())
        chip = f"[{label:^{CHIP_WIDTH}}]"
        if status == "hit":
            return Text(chip, style=f"bold {self.stamp_fg} on {self.stamp}")
        return Text(chip, style=f"bold {self.status_colour(status)}")


# Block glyphs for the default wordmark. Five cells wide, five rows tall; only
# the letters "EMAIL SPY" needs are kept, so a theme with any other wordmark
# falls back to plain text.
_BANNER: dict[str, tuple[str, ...]] = {
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "M": ("█   █", "██ ██", "█ █ █", "█   █", "█   █"),
    "A": (" ███ ", "█   █", "█████", "█   █", "█   █"),
    "I": ("█████", "  █  ", "  █  ", "  █  ", "█████"),
    "L": ("█    ", "█    ", "█    ", "█    ", "█████"),
    "S": (" ████", "█    ", " ███ ", "    █", "████ "),
    "P": ("████ ", "█   █", "████ ", "█    ", "█    "),
    "Y": ("█   █", " █ █ ", "  █  ", "  █  ", "  █  "),
}


def banner_rows(wordmark: str) -> list[str] | None:
    """Render ``wordmark`` as five rows of block glyphs, or None if unsupported."""
    glyphs: list[str | None] = []
    for char in wordmark.upper():
        if char == " ":
            glyphs.append(None)
        elif char in _BANNER:
            glyphs.append(char)
        else:
            return None
    if not glyphs or not any(glyphs):
        return None
    rows: list[str] = []
    for row in range(5):
        cells = [" " if glyph is None else _BANNER[glyph][row] for glyph in glyphs]
        rows.append(" ".join(cells))
    return rows


SPY = Theme(
    name="spy",
    wordmark="EMAIL SPY",
    signal="#5AD1C6",
    stamp="#FFB020",
    remote="#79B8FF",
    alert="#FF6B6B",
    warn="#FFD166",
    graphite="#72808E",
    ink="#C7D0D8",
    summary="#AEBAC5",
    steel="#22303A",
    muted="#6B7680",
    stamp_fg="#10161B",
)

CLASSIC = Theme(
    name="classic",
    wordmark="EMAILSCOPE",
    signal="#5FD7FF",
    stamp="#5FD7AF",
    remote="#6FA8FF",
    alert="#FF6B6B",
    warn="#FFD75F",
    graphite="#8A8A8A",
    ink="#E6E6E6",
    summary="#C8C8C8",
    steel="#2E2E2E",
    muted="#8A8A8A",
    stamp_fg="#0B0F12",
)

THEMES: dict[str, Theme] = {theme.name: theme for theme in (SPY, CLASSIC)}
DEFAULT_THEME = "spy"


def get_theme(name: str | None) -> Theme:
    if not name:
        return SPY
    return THEMES.get(name, SPY)
