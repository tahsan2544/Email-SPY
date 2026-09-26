"""Gravatar avatar handling: only a real fetched image is ever shown."""

import asyncio
import json

import httpx

from emailscope.context import Context, Options
from emailscope.models import Case, Finding
from emailscope.modules import gravatar
from emailscope.modules import identity as identity_module
from emailscope.report import default_rows, to_json

JPEG = b"\xff\xd8\xff\xe0fake-jpeg-bytes"


class _ScriptedClient:
    def __init__(self, responses: dict[str, httpx.Response]):
        self.responses = responses

    async def get(self, url: str, **kwargs):
        for key, response in self.responses.items():
            if key in url:
                return response
        raise AssertionError(f"unexpected url {url}")


def _collect(responses: dict[str, httpx.Response], email: str = "john.doe@example.com"):
    parsed = identity_module.parse_email(email)
    assert parsed.valid
    context = Context(
        email=parsed.email, identity=parsed, client=_ScriptedClient(responses), options=Options()
    )
    return asyncio.run(gravatar.collect(context))


def _no_profile() -> dict[str, httpx.Response]:
    return {
        "api.gravatar.com": httpx.Response(404),
        "gravatar.com/avatar": httpx.Response(404),
        "en.gravatar.com": httpx.Response(404),
    }


def test_avatar_image_is_embedded_and_linked():
    responses = _no_profile()
    responses["gravatar.com/avatar"] = httpx.Response(
        200, content=JPEG, headers={"content-type": "image/jpeg"}
    )
    finding = _collect(responses)

    assert finding.status == "info"
    assert finding.data["avatar"] is True
    assert finding.data["avatar_datauri"].startswith("data:image/jpeg;base64,")
    assert finding.links[0]["label"] == "Avatar"
    assert finding.links[0]["url"].endswith("d=404&s=200")


def test_missing_avatar_says_missing_and_fabricates_nothing():
    finding = _collect(_no_profile())

    assert finding.summary == "No Gravatar account for this address."
    assert finding.data["avatar"] is False
    assert "avatar_datauri" not in finding.data
    assert finding.links == []


def test_a_blocked_html_page_is_not_called_a_picture():
    responses = _no_profile()
    responses["gravatar.com/avatar"] = httpx.Response(
        200, content=b"<html>blocked</html>", headers={"content-type": "text/html"}
    )
    finding = _collect(responses)

    assert finding.data["avatar"] is False
    assert "avatar_datauri" not in finding.data
    assert finding.summary == "No Gravatar account for this address."


def test_oversized_image_is_linked_but_not_embedded():
    responses = _no_profile()
    responses["gravatar.com/avatar"] = httpx.Response(
        200,
        content=b"\x89PNG" + b"a" * gravatar.EMBED_LIMIT,
        headers={"content-type": "image/png"},
    )
    finding = _collect(responses)

    assert finding.data["avatar"] is True
    assert "avatar_datauri" not in finding.data
    assert finding.links[0]["label"] == "Avatar"


def test_profile_with_avatar_keeps_picture_and_lists_it_first():
    responses = _no_profile()
    responses["api.gravatar.com"] = httpx.Response(
        200,
        json={
            "display_name": "Jane Doe",
            "profile_url": "https://gravatar.com/jane",
            "location": "",
            "job_title": "",
            "company": "",
            "description": "",
            "verified_accounts": [{"service_label": "GitHub", "url": "https://github.com/jane"}],
        },
    )
    responses["gravatar.com/avatar"] = httpx.Response(
        200, content=JPEG, headers={"content-type": "image/jpeg"}
    )
    finding = _collect(responses)

    assert finding.status == "hit"
    assert finding.data["avatar"] is True
    assert finding.links[0] == {
        "label": "Avatar",
        "url": "https://www.gravatar.com/avatar/"
        f"{identity_module.parse_email('john.doe@example.com').gravatar_sha256}"
        "?d=404&s=200",
    }
    assert finding.links[1]["label"] == "GitHub"


def test_avatar_datauri_never_reaches_terminal_rows_or_json():
    finding = Finding(
        module="gravatar",
        title="Gravatar",
        status="info",
        data={"avatar": True, "avatar_datauri": "data:image/jpeg;base64,AAAA"},
    )
    case = Case(email="john.doe@example.com", findings=[finding])

    labels = [label for label, _ in default_rows(finding.data)]
    assert "Avatar Datauri" not in labels
    assert ("Avatar", True) in default_rows(finding.data)

    assert "avatar_datauri" not in to_json(case)
    assert "data:image/jpeg" not in json.dumps(json.loads(to_json(case)))
