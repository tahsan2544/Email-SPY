"""OpenPGP lookup against keys.openpgp.org.

The directory only serves keys whose user ID carries a *verified* copy of the
queried address, so a hit is a strong signal and the other user IDs on the key
are the interesting part — they are addresses the owner published themselves.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from emailscope.context import Context
from emailscope.models import Finding

LOOKUP_URL = "https://keys.openpgp.org/vks/v1/by-email/{email}"
FINGERPRINT_URL = "https://keys.openpgp.org/vks/v1/by-fingerprint/{fingerprint}"

# Armor Comment headers carry the fingerprint as grouped hex and each user ID
# as "Name <address>"; base64 payload lines cannot contain a colon, so scanning
# for "Comment:" is safe.
_FINGERPRINT = re.compile(r"^(?:[0-9A-Fa-f]{4}\s+){9}[0-9A-Fa-f]{4}$")
_USER_ID = re.compile(r"^(?P<name>.*?)\s*<(?P<email>[^<>]+)>\s*$")


def parse_key(body: str) -> tuple[str | None, list[str]]:
    """Fingerprint and user IDs advertised in an armored key's Comment headers."""
    fingerprint: str | None = None
    user_ids: list[str] = []
    for line in body.splitlines():
        if not line.startswith("Comment:"):
            continue
        value = line[len("Comment:") :].strip()
        if _FINGERPRINT.match(value):
            fingerprint = re.sub(r"\s+", "", value).upper()
            continue
        match = _USER_ID.match(value)
        if match and "@" in match.group("email"):
            user_ids.append(f"{match.group('name').strip()} <{match.group('email').strip()}>")
    return fingerprint, user_ids


def _addresses(user_ids: list[str]) -> list[str]:
    found = []
    for user_id in user_ids:
        match = _USER_ID.match(user_id)
        if match:
            found.append(match.group("email"))
    return sorted(dict.fromkeys(found))


async def collect(context: Context) -> Finding:
    if not context.options.pgp:
        return Finding(module="pgp", title="PGP key", status="skip", summary="Disabled.")
    identity = context.identity
    if not identity.valid:
        return Finding(module="pgp", title="PGP key", status="skip", summary="Invalid address.")

    response = await context.client.get(
        LOOKUP_URL.format(email=quote(identity.email, safe="")), retries=1
    )
    if response.status_code == 404:
        return Finding(
            module="pgp",
            title="PGP key",
            status="info",
            summary="No published key for this address.",
        )
    if response.status_code != 200:
        return Finding(
            module="pgp",
            title="PGP key",
            status="unknown",
            summary=f"keys.openpgp.org returned HTTP {response.status_code}.",
        )

    fingerprint, user_ids = parse_key(response.text)
    if not fingerprint and not user_ids:
        return Finding(
            module="pgp",
            title="PGP key",
            status="unknown",
            summary="Key returned without readable metadata.",
        )

    addresses = _addresses(user_ids)
    others = [a for a in addresses if a.lower() != identity.email.lower()]
    data: dict[str, object] = {
        "fingerprint": fingerprint or "",
        "user_ids": user_ids,
        "other_addresses": others,
    }
    links = []
    if fingerprint:
        links.append({"label": "PGP key", "url": FINGERPRINT_URL.format(fingerprint=fingerprint)})

    bits = [f"{len(user_ids)} user ID(s)"]
    if others:
        bits.append("also published: " + ", ".join(others))
    return Finding(
        module="pgp",
        title="PGP key",
        status="hit",
        summary=" · ".join(bits),
        data=data,
        links=links,
    )
