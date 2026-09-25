import pytest

from emailscope.http import USER_AGENT, HttpClient


def test_client_sets_the_stable_user_agent():
    assert USER_AGENT.startswith("emailspy/")


@pytest.mark.parametrize(
    "proxy",
    [
        "http://127.0.0.1:8080",
        "socks5://127.0.0.1:9150",
        "socks5h://127.0.0.1:9150",
    ],
)
def test_client_accepts_proxies(proxy):
    """A proxy URL must build a client — this fails loudly if httpx[socks] is missing."""

    async def build():
        client = HttpClient(proxy=proxy)
        await client.aclose()

    import asyncio

    asyncio.run(build())
