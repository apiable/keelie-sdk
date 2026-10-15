from __future__ import annotations

import asyncio

import httpx
import pytest
from support import ISSUER, Clock

from apiable import (
    AiCatalog,
    McpGuard,
    MissingTokenChallenge,
    ProtectedResourceMetadata,
    TokenGuard,
    UsageReporter,
)
from apiable.catalog import KEELIE_PATH
from apiable.discovery import ASGIApp, Receive, Scope, Send

KEELIE = "https://keelie.example.test"
# A resource at the root: every path is under it, so the guards must let the catalog pass.
RESOURCE = "https://api.example.test"


class Keelie:
    """keelie's catalog endpoint, served without a network."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.body = b'{"specVersion":"1.0","entries":[]}'
        self.answer: int | Exception = 200

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        # Yield, as a real fetch does, so that concurrent requests overlap.
        await asyncio.sleep(0.01)
        if isinstance(self.answer, Exception):
            raise self.answer
        return httpx.Response(self.answer, content=self.body)


async def _provider(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def _guarded(keelie: Keelie, clock: Clock, guard: str) -> ASGIApp:
    client = httpx.AsyncClient(base_url=KEELIE, transport=httpx.MockTransport(keelie.handler))
    catalog = AiCatalog(_provider, client, clock=clock)
    metadata = ProtectedResourceMetadata(RESOURCE, ISSUER)
    verifier = None  # never reached: the catalog needs no token
    if guard == "challenge":
        return MissingTokenChallenge(catalog, metadata)
    if guard == "rest":
        return TokenGuard(catalog, verifier, metadata)  # type: ignore[arg-type]
    reporter = UsageReporter(client)
    return McpGuard(catalog, verifier, metadata, {}, reporter=reporter)  # type: ignore[arg-type]


async def _get(app: ASGIApp, method: str = "GET") -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=RESOURCE) as client:
        return await client.request(method, "/.well-known/ai-catalog.json")


@pytest.mark.parametrize("guard", ["challenge", "rest", "mcp"])
async def test_the_catalog_is_keelies_document_with_no_token(guard: str) -> None:
    keelie = Keelie()

    response = await _get(_guarded(keelie, Clock(), guard))

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/ai-catalog+json"
    assert response.content == keelie.body
    assert response.headers["cache-control"] == "max-age=60"
    assert keelie.paths == [KEELIE_PATH]


async def test_head_answers_the_length_and_no_body() -> None:
    keelie = Keelie()

    response = await _get(_guarded(keelie, Clock(), "rest"), "HEAD")

    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["content-length"] == str(len(keelie.body))


async def test_a_copy_is_kept_for_60_seconds_and_no_longer() -> None:
    keelie, clock = Keelie(), Clock()
    app = _guarded(keelie, clock, "rest")
    await _get(app)
    keelie.body = b'{"specVersion":"1.0","entries":[{"identifier":"x"}]}'

    clock.now += 59
    cached = await _get(app)
    clock.now += 1
    fresh = await _get(app)

    assert len(keelie.paths) == 2
    assert cached.content == b'{"specVersion":"1.0","entries":[]}'
    # A plan published in keelie shows within 60 seconds.
    assert fresh.content == keelie.body


@pytest.mark.parametrize("failure", [503, httpx.ConnectError("down")], ids=["503", "network"])
async def test_an_old_copy_is_never_served_when_keelie_fails(failure: int | Exception) -> None:
    keelie, clock = Keelie(), Clock()
    app = _guarded(keelie, clock, "rest")
    await _get(app)
    keelie.answer = failure

    clock.now += 60
    response = await _get(app)

    assert response.status_code == 503
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"


async def test_after_a_failure_keelie_is_asked_again_after_10_seconds_not_on_each_request() -> None:
    """The path is public. Traffic to it must not turn into one call to keelie for each
    request, with the Provider's credential, while keelie fails."""
    keelie, clock = Keelie(), Clock()
    app = _guarded(keelie, clock, "rest")
    keelie.answer = 503

    answers = await asyncio.gather(*(_get(app) for _ in range(20)))
    clock.now += 9
    still = await _get(app)
    keelie.answer = 200
    clock.now += 1
    recovered = await _get(app)

    assert [answer.status_code for answer in answers] == [503] * 20
    assert still.status_code == 503
    assert recovered.status_code == 200
    assert len(keelie.paths) == 2
