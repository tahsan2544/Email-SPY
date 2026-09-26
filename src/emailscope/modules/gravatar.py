"""Gravatar lookup — the only widely used service keyed directly by email hash."""

from __future__ import annotations

import base64
from typing import Any

from emailscope.context import Context
from emailscope.models import Finding

PROFILE_URL = "https://api.gravatar.com/v3/profiles/{sha256}"
AVATAR_URL = "https://www.gravatar.com/avatar/{sha256}?d=404&s=200"
LEGACY_PROFILE_URL = "https://en.gravatar.com/{md5}.json"

# The HTML report embeds the fetched bytes so the file still shows the picture
# with no network. Bigger responses are linked instead of embedded.
EMBED_LIMIT = 300_000


async def collect(context: Context) -> Finding:
    if not context.options.gravatar:
        return Finding(module="gravatar", title="Gravatar", status="skip", summary="Disabled.")
    identity = context.identity
    if not identity.valid:
        return Finding(
            module="gravatar", title="Gravatar", status="skip", summary="Invalid address."
        )

    profile_url = PROFILE_URL.format(sha256=identity.gravatar_sha256)
    links: list[dict[str, str]] = []
    data: dict[str, Any] = {"hash": identity.gravatar_sha256}

    profile: dict[str, Any] | None = None
    response = await context.client.get(profile_url, retries=1)
    if response.status_code == 200:
        try:
            profile = response.json()
        except ValueError:
            profile = None

    avatar = await context.client.get(AVATAR_URL.format(sha256=identity.gravatar_sha256), retries=1)
    avatar_status = avatar.status_code
    avatar_mime = ""
    if avatar_status == 200:
        avatar_mime = (avatar.headers.get("content-type") or "").partition(";")[0].strip().lower()
    # Only an actual image counts as an avatar — a 200 HTML page is not a picture.
    has_avatar = avatar_mime.startswith("image/")
    avatar_datauri = ""
    if has_avatar and len(avatar.content) <= EMBED_LIMIT:
        encoded = base64.b64encode(avatar.content).decode("ascii")
        avatar_datauri = f"data:{avatar_mime};base64,{encoded}"

    if profile is None and not has_avatar:
        legacy = await context.client.get(
            LEGACY_PROFILE_URL.format(md5=identity.gravatar_md5), retries=1
        )
        if legacy.status_code == 200:
            try:
                entries = legacy.json().get("entry") or []
            except ValueError:
                entries = []
            if entries:
                profile = {"legacy": entries[0]}

    if profile is None:
        if has_avatar:
            finding = Finding(
                module="gravatar",
                title="Gravatar",
                status="info",
                summary="Avatar registered for this address, but no public profile.",
                data={
                    **data,
                    "avatar": True,
                    "avatar_url": AVATAR_URL.format(sha256=identity.gravatar_sha256),
                    "profile": None,
                },
                links=[
                    {"label": "Avatar", "url": AVATAR_URL.format(sha256=identity.gravatar_sha256)}
                ],
            )
            if avatar_datauri:
                finding.data["avatar_datauri"] = avatar_datauri
            return finding
        return Finding(
            module="gravatar",
            title="Gravatar",
            status="info",
            summary="No Gravatar account for this address.",
            data={**data, "avatar": False, "profile": None},
        )

    if "legacy" in profile:
        entry = profile["legacy"]
        profile = {
            "display_name": entry.get("displayName", ""),
            "profile_url": entry.get("profileUrl", ""),
            "location": "",
            "job_title": "",
            "company": "",
            "description": "",
            "verified_accounts": [],
        }

    display_name = (profile.get("display_name") or "").strip()
    location = (profile.get("location") or "").strip()
    job_title = (profile.get("job_title") or "").strip()
    company = (profile.get("company") or "").strip()
    description = (profile.get("description") or "").strip()
    profile_page = (profile.get("profile_url") or "").strip()
    verified = profile.get("verified_accounts") or []

    accounts = []
    for account in verified:
        if not isinstance(account, dict):
            continue
        url = account.get("url") or ""
        label = account.get("service_label") or account.get("service_type") or url
        if url:
            accounts.append({"service": label, "url": url})
            links.append({"label": label, "url": url})

    if profile_page:
        links.append({"label": "Gravatar profile", "url": profile_page})

    if has_avatar:
        avatar_url = AVATAR_URL.format(sha256=identity.gravatar_sha256)
        links.insert(0, {"label": "Avatar", "url": avatar_url})

    data.update(
        {
            "avatar": has_avatar,
            "avatar_url": profile.get("avatar_url")
            or AVATAR_URL.format(sha256=identity.gravatar_sha256),
            "display_name": display_name,
            "profile_url": profile_page,
            "location": location,
            "job_title": job_title,
            "company": company,
            "description": description,
            "verified_accounts": accounts,
        }
    )
    if avatar_datauri:
        data["avatar_datauri"] = avatar_datauri

    bits = [b for b in (display_name, job_title, company, location) if b]
    summary = ", ".join(bits) if bits else "Public Gravatar profile found."
    if accounts:
        summary += f" · {len(accounts)} linked account(s)"

    return Finding(
        module="gravatar",
        title="Gravatar profile",
        status="hit",
        summary=summary,
        data=data,
        links=links,
    )
