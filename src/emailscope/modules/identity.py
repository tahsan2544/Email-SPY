"""Local, offline analysis of the address itself: validity, provider, name guesses."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import TYPE_CHECKING

from emailscope.models import Finding

if TYPE_CHECKING:  # pragma: no cover
    from emailscope.context import Context

_EMAIL_RE = re.compile(
    r"^(?P<local>[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+)@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})$"
)
_TOKEN_SPLIT_RE = re.compile(r"[._\-+]+")
_STOPWORDS = {
    "info",
    "admin",
    "contact",
    "support",
    "sales",
    "team",
    "mail",
    "email",
    "hello",
    "hi",
    "me",
    "the",
    "and",
    "for",
    "official",
    "officialaccount",
    "office",
    "hr",
    "jobs",
    "careers",
    "billing",
    "noreply",
    "no_reply",
    "donotreply",
    "postmaster",
    "webmaster",
    "abuse",
    "security",
    "dept",
    "department",
    "eng",
    "dev",
    "test",
    "user",
    "users",
    "customer",
    "customers",
    "service",
    "services",
    "my",
    "its",
    "real",
}


def _load_json(name: str) -> dict:
    ref = resources.files("emailscope.data").joinpath(name)
    return json.loads(ref.read_text(encoding="utf-8"))


@dataclass
class Identity:
    email: str
    valid: bool
    local: str = ""
    domain: str = ""
    provider: str | None = None
    is_free_provider: bool = False
    is_disposable: bool = False
    name_candidates: list[str] = field(default_factory=list)
    handle_candidates: list[str] = field(default_factory=list)
    gravatar_md5: str = ""
    gravatar_sha256: str = ""
    tag: str | None = None
    problems: list[str] = field(default_factory=list)


def normalize(email: str) -> str:
    return email.strip().lower()


def parse_email(raw: str) -> Identity:
    """Validate and decompose an address. Never raises on user input."""
    email = normalize(raw)
    identity = Identity(email=email, valid=False)

    if not email or "@" not in email:
        identity.problems.append("address is empty or has no @ sign")
        return identity

    match = _EMAIL_RE.match(email)
    if not match:
        identity.problems.append("address does not match a valid email shape")
        return identity

    local = match.group("local")
    domain = match.group("domain")
    identity.local = local
    identity.domain = domain
    identity.valid = True

    if "+" in local:
        identity.tag = local.split("+", 1)[1]

    data = _load_json("providers.json")
    providers = {k.lower(): v.get("name", k) for k, v in data.get("free_providers", {}).items()}
    disposable = {d.lower() for d in data.get("disposable", [])}

    identity.provider = providers.get(domain)
    identity.is_free_provider = identity.provider is not None
    identity.is_disposable = domain in disposable
    if domain.startswith("www."):
        identity.is_disposable = domain[4:] in disposable

    identity.name_candidates = _name_candidates(local)
    identity.handle_candidates = handles_from_local(local)
    identity.gravatar_md5 = hashlib.md5(email.encode("utf-8")).hexdigest()
    identity.gravatar_sha256 = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return identity


def _is_word(token: str) -> bool:
    return len(token) >= 2 and token.isalpha() and token.lower() not in _STOPWORDS


def _name_candidates(local: str) -> list[str]:
    """Best-effort display names derived from the local part.

    ``john.doe``, ``john_doe`` and ``doe.john`` all yield sensible guesses;
    opaque local parts such as ``x7q2p9`` yield nothing.
    """
    base = local.split("+", 1)[0]
    cleaned = re.sub(r"\d{2,}", "", base)
    tokens = [t for t in _TOKEN_SPLIT_RE.split(cleaned) if _is_word(t)]
    if not tokens:
        return []

    candidates: list[str] = []

    def add(full: str) -> None:
        full = full.strip()
        if full and full not in candidates:
            candidates.append(full)

    add(" ".join(t.capitalize() for t in tokens))
    if len(tokens) >= 2:
        add(" ".join(t.capitalize() for t in reversed(tokens)))
        add(f"{tokens[0][0].upper()}. {' '.join(t.capitalize() for t in tokens[1:])}")
        add(f"{' '.join(t.capitalize() for t in tokens[:-1])} {tokens[-1][0].upper()}.")
    return candidates


def handles_from_local(local: str) -> list[str]:
    """Usernames worth probing on public profile endpoints, from the local part."""
    base = re.sub(r"[^a-z0-9._-]", "", local.split("+", 1)[0].lower())
    handles: list[str] = []

    def add(value: str) -> None:
        value = value.strip("._-")
        if 2 <= len(value) <= 32 and value not in handles:
            handles.append(value)

    add(base)
    parts = [p for p in _TOKEN_SPLIT_RE.split(base) if p]
    if len(parts) >= 2:
        add("".join(parts))
        add(f"{parts[0][0]}{parts[-1]}")
        add(f"{parts[0]}{parts[-1][0]}")
        add(".".join(parts))
        add("_".join(parts))
    add(re.sub(r"\d", "", base))
    return handles[:6]


def handles_from_name(name: str) -> list[str]:
    """Username shapes derived from an observed real name (e.g. a git author)."""
    tokens = [p for p in re.split(r"[\s._\-+,]+", name.strip()) if p]
    parts = [p for p in tokens if p.isalpha() and len(p) > 1]
    handles: list[str] = []

    def add(value: str) -> None:
        value = value.lower()
        if 3 <= len(value) <= 32 and value not in handles:
            handles.append(value)

    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        add(f"{first}{last}")
        add(f"{first}.{last}")
        add(f"{first}_{last}")
        add(f"{first[0]}{last}")
        add(last)
    elif parts:
        add(parts[0])
    return handles[:5]


def analyse(raw_email: str) -> Finding:
    identity = parse_email(raw_email)
    if not identity.valid:
        return Finding(
            module="identity",
            title="Address",
            status="error",
            summary="; ".join(identity.problems) or "invalid address",
            data={"email": identity.email, "valid": False, "problems": identity.problems},
        )

    if identity.is_disposable:
        summary = "Disposable/throwaway domain — expected to be short-lived."
    elif identity.is_free_provider:
        summary = f"Consumer mailbox hosted by {identity.provider}."
    else:
        summary = f"Custom domain ({identity.domain})."

    return Finding(
        module="identity",
        title="Address",
        status="info",
        summary=summary,
        data={
            "email": identity.email,
            "valid": True,
            "local_part": identity.local,
            "domain": identity.domain,
            "provider": identity.provider,
            "free_provider": identity.is_free_provider,
            "disposable": identity.is_disposable,
            "plus_tag": identity.tag,
            "name_candidates": identity.name_candidates,
            "handle_candidates": identity.handle_candidates,
            "gravatar_md5": identity.gravatar_md5,
            "gravatar_sha256": identity.gravatar_sha256,
        },
    )


async def analyse_async(context: Context) -> Finding:
    """Async adapter so the identity check can run alongside the network modules."""
    if not context.options.identity:
        return Finding(module="identity", title="Address", status="skip", summary="Disabled.")
    return analyse(context.email)
