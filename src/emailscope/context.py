"""Run context shared by every collection module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from emailscope.http import HttpClient

if TYPE_CHECKING:  # pragma: no cover
    from emailscope.modules.identity import Identity


@dataclass
class Options:
    """Feature switches resolved from CLI flags and environment."""

    identity: bool = True
    accounts: bool = True
    social: bool = True
    smtp: bool = True
    gravatar: bool = True
    github: bool = True
    mentions: bool = True
    dns: bool = True
    dorks: bool = True
    pgp: bool = True
    rdap: bool = True
    ct: bool = True
    hosts: bool = True
    mailhost: bool = True
    urlscan: bool = True
    reputation: bool = True
    breaches: bool = True
    open_links: bool = False
    timeout: float = 12.0
    rate_limit: float = 0.0
    proxy: str | None = None
    env: dict[str, str] = field(default_factory=dict)

    def key(self, name: str) -> str | None:
        value = self.env.get(name, "").strip()
        return value or None


@dataclass
class Context:
    email: str
    identity: Identity
    client: HttpClient
    options: Options
    extra: dict[str, Any] = field(default_factory=dict)
