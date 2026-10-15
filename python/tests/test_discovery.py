from __future__ import annotations

import httpx
import pytest

from apiable import MissingTokenChallenge, ProtectedResourceMetadata
from apiable.discovery import Message, Receive, Scope, Send

RESOURCE = "https://api.example.test/mcp"
ISSUER = "https://issuer.example.test/realms/test"
METADATA_URL = "https://api.example.test/.well-known/oauth-protected-resource/mcp"
CHALLENGE = f'Bearer resource_metadata="{METADATA_URL}"'


class App:
    """The Provider's app: answers 204 and remembers each scope type it saw."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.seen.append(str(scope["type"]))
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})


def _client(app: App, resource: str = RESOURCE) -> httpx.AsyncClient:
    middleware = MissingTokenChallenge(app, ProtectedResourceMetadata(resource, ISSUER))
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=middleware), base_url="https://api.example.test"
    )


async def test_the_metadata_names_the_resource_and_one_issuer() -> None:
    async with _client(App()) as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    }


@pytest.mark.parametrize(
    "authorization", [None, "Basic dXNlcjpwYXNz", "Bearer ", "Bearer", "bearer  "]
)
async def test_a_request_with_no_bearer_token_gets_401_and_the_challenge(
    authorization: str | None,
) -> None:
    app = App()
    headers = {} if authorization is None else {"Authorization": authorization}
    async with _client(app) as client:
        response = await client.post("/mcp", headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == CHALLENGE
    assert response.content == b""
    assert app.seen == []


async def test_a_forged_host_does_not_move_the_challenge() -> None:
    async with _client(App()) as client:
        response = await client.get("/mcp/tools", headers={"Host": "attacker.example.test"})

    assert response.headers["www-authenticate"] == CHALLENGE


@pytest.mark.parametrize("authorization", ["Bearer x", "bearer x"])
async def test_any_bearer_token_passes_to_the_app_unverified(authorization: str) -> None:
    # The middleware checks presence only. The app verifies the token.
    app = App()
    async with _client(app) as client:
        response = await client.get("/mcp/tools", headers={"Authorization": authorization})

    assert response.status_code == 204
    assert app.seen == ["http"]


@pytest.mark.parametrize("path", ["/mcpx", "/health"])
async def test_a_path_outside_the_resource_passes_with_no_token(path: str) -> None:
    async with _client(App()) as client:
        response = await client.get(path)

    assert response.status_code == 204


async def test_a_resource_at_the_root_serves_its_metadata_with_no_token() -> None:
    root = "https://api.example.test"
    async with _client(App(), root) as client:
        metadata = await client.get("/.well-known/oauth-protected-resource")
        refused = await client.get("/orders")

    assert metadata.status_code == 200
    assert metadata.json()["resource"] == root
    assert refused.status_code == 401
    assert refused.headers["www-authenticate"] == (
        'Bearer resource_metadata="https://api.example.test/.well-known/oauth-protected-resource"'
    )


@pytest.mark.parametrize("kind", ["lifespan", "websocket"])
async def test_a_scope_that_is_not_http_passes_to_the_app(kind: str) -> None:
    app = App()
    middleware = MissingTokenChallenge(app, ProtectedResourceMetadata(RESOURCE, ISSUER))

    async def receive() -> Message:
        return {"type": f"{kind}.connect"}

    async def send(message: Message) -> None:
        pass

    await middleware({"type": kind, "path": "/mcp"}, receive, send)

    assert app.seen == [kind]


async def test_a_cors_preflight_passes_with_no_token() -> None:
    async with _client(App()) as client:
        response = await client.options("/mcp")

    assert response.status_code == 204


def test_the_challenge_for_a_refused_token_carries_the_error() -> None:
    metadata = ProtectedResourceMetadata(RESOURCE, ISSUER)

    assert metadata.challenge("invalid_token") == (
        f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
    )


@pytest.mark.parametrize(
    "resource",
    [
        "http://api.example.test/mcp",
        "https://api.example.test/mcp?x=1",
        "https://api.example.test/mcp#x",
        'https://api.example.test/m"cp',
        "https://user:secret@api.example.test/mcp",
        "https://api.example.test:port/mcp",
        "https://api.example.test/mcp/",
        "/mcp",
    ],
)
def test_a_resource_that_is_not_a_plain_https_url_is_refused(resource: str) -> None:
    with pytest.raises(ValueError):
        ProtectedResourceMetadata(resource, ISSUER)


def test_scopes_are_published_only_as_a_list() -> None:
    metadata = ProtectedResourceMetadata(RESOURCE, ISSUER, scopes_supported=["orders:read"])

    assert b'"scopes_supported":["orders:read"]' in metadata.document
    with pytest.raises(ValueError):
        ProtectedResourceMetadata(RESOURCE, ISSUER, scopes_supported="orders:read")


@pytest.mark.parametrize(
    ("resource", "path", "protected"),
    [
        ("https://api.example.test", "/.well-known/ai-catalog.json", False),
        ("https://api.example.test", "/.well-known/ai-catalog.json/x", True),
        ("https://api.example.test", "/.well-known/ai-catalog.json.bak", True),
        (RESOURCE, "/.well-known/ai-catalog.json", False),
    ],
)
def test_only_the_exact_ai_catalog_path_needs_no_token(
    resource: str, path: str, protected: bool
) -> None:
    assert ProtectedResourceMetadata(resource, ISSUER).protects(path) is protected
