from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from support import ISSUER, ORG_ID, Clock, Issuer, signed_token

from apiable import McpGuard, ProtectedResourceMetadata, TokenVerifier, UsageReporter
from apiable.keys import SigningKeys
from apiable.discovery import Receive, Scope, Send
from apiable.mcp import INSUFFICIENT_SCOPE, INVALID_PARAMS, INVALID_REQUEST, PARSE_ERROR

RESOURCE = "https://api.example.test/mcp"
METADATA_URL = "https://api.example.test/.well-known/oauth-protected-resource/mcp"

# Each tool and its one scope. Inside the adapter, the ScopeMap key of a tool
# is ("tools/call", <tool name>).
TOOLS = {"get_order": "orders:read", "cancel_order": "orders:write"}


class Server:
    """The Provider's MCP server: keeps each body, answers with ``status``, as JSON or SSE."""

    def __init__(self) -> None:
        self.bodies: list[bytes] = []
        self.status = 200
        self.sse = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = b""
        if scope["method"] == "POST":
            message = await receive()
            body = bytes(message["body"])  # type: ignore[arg-type]
            assert not message.get("more_body")
        self.bodies.append(body)
        kind = b"text/event-stream" if self.sse else b"application/json"
        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [(b"content-type", kind)],
            }
        )
        if self.sse:
            await send({"type": "http.response.body", "body": b"data: 1\n\n", "more_body": True})
            await send({"type": "http.response.body", "body": b"data: 2\n\n"})
        else:
            await send({"type": "http.response.body", "body": b"{}"})


class Keelie:
    """keelie's usage endpoint: keeps each event it gets."""

    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.events.extend(json.loads(request.content)["events"])
        return httpx.Response(200)


@pytest.fixture
def server() -> Server:
    return Server()


@pytest.fixture
def keelie() -> Keelie:
    return Keelie()


@pytest.fixture
async def reporter(keelie: Keelie) -> AsyncIterator[UsageReporter]:
    reporter = UsageReporter(
        httpx.AsyncClient(
            transport=httpx.MockTransport(keelie.handler), base_url="https://keelie.example.test"
        )
    )
    yield reporter
    await reporter.aclose()


@pytest.fixture
async def client(
    verifier: TokenVerifier, server: Server, reporter: UsageReporter
) -> AsyncIterator[httpx.AsyncClient]:
    guard = McpGuard(
        server,
        verifier,
        ProtectedResourceMetadata(RESOURCE, ISSUER),
        TOOLS,
        reporter=reporter,
        max_body_bytes=1024 * 1024,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=guard), base_url="https://api.example.test"
    ) as client:
        yield client


@pytest.fixture
def verifier(issuer: Issuer, clock: Clock) -> TokenVerifier:
    """The MCP server's verifier: its audience is the MCP endpoint, its ``resource``."""
    client = httpx.AsyncClient(transport=httpx.MockTransport(issuer.handler))
    keys = SigningKeys(ISSUER, client=client, clock=clock)
    return TokenVerifier(ISSUER, RESOURCE, ORG_ID, keys=keys)


def _auth(key: RSAPrivateKey, scope: str = "orders:read orders:write") -> dict[str, str]:
    return {"Authorization": f"Bearer {signed_token(key, scope=scope, aud=RESOURCE)}"}


def _call(tool: object, request_id: object = 7) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool}}
    ).encode()


async def test_a_tool_call_with_the_scope_reaches_the_server_unchanged(
    client: httpx.AsyncClient, server: Server, signing_key: RSAPrivateKey
) -> None:
    body = _call("get_order")
    response = await client.post("/mcp", content=body, headers=_auth(signing_key, "orders:read"))

    assert response.status_code == 200
    assert server.bodies == [body]


@pytest.mark.parametrize(
    ("tool", "scope"),
    [
        ("get_order", "orders:write"),  # another tool's scope
        ("get_order", ""),
        ("get_order", "orders"),  # a scope matches only itself
        ("GET_ORDER", "orders:read orders:write"),  # a tool name matches only itself
        ("unmapped", "orders:read orders:write"),  # not in the map: refused
        ("x\napiable.forged line", "orders:read orders:write"),  # stays out of the log
    ],
)
async def test_a_token_without_the_tools_scope_cannot_call_it(
    client: httpx.AsyncClient,
    server: Server,
    signing_key: RSAPrivateKey,
    caplog: pytest.LogCaptureFixture,
    tool: str,
    scope: str,
) -> None:
    caplog.set_level(logging.INFO)
    response = await client.post("/mcp", content=_call(tool), headers=_auth(signing_key, scope))

    assert response.status_code == 403
    assert response.headers["www-authenticate"] == (
        f'Bearer error="insufficient_scope", resource_metadata="{METADATA_URL}"'
    )
    # The same answer for an unmapped tool and an unscoped one: no scope is named.
    assert response.json() == {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {"code": INSUFFICIENT_SCOPE, "message": "Insufficient scope"},
    }
    assert server.bodies == []
    # A tool name that is not in the map comes from the request: it is not logged.
    assert all(
        "\n" not in r.getMessage() and "forged" not in r.getMessage() for r in caplog.records
    )


@pytest.mark.parametrize(
    ("body", "status", "code", "request_id"),
    [
        (b"{not json", 400, PARSE_ERROR, None),
        (b"\xff\xfe", 400, PARSE_ERROR, None),
        pytest.param(b"[" * 200_000 + b"]" * 200_000, 400, PARSE_ERROR, None, id="deep"),
        (b"[" + _call("get_order") + b"]", 400, INVALID_REQUEST, None),  # a batch
        (b"1", 400, INVALID_REQUEST, None),
        (
            (
                b'{"jsonrpc":"2.0","id":7,"method":"tools/call",'
                b'"params":{"name":"get_order","name":"cancel_order"}}'
            ),
            400,
            INVALID_REQUEST,
            None,
        ),
        (
            b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_order"}}',
            400,
            INVALID_REQUEST,
            None,
        ),
        (_call("get_order", None), 400, INVALID_REQUEST, None),
        (_call("get_order", True), 400, INVALID_REQUEST, None),
        (_call(42), 400, INVALID_PARAMS, 7),
        (b'{"jsonrpc":"2.0","id":7,"method":"tools/call"}', 400, INVALID_PARAMS, 7),
        (_call("x" * 1024 * 1024), 413, INVALID_REQUEST, None),
    ],
)
async def test_a_body_the_adapter_cannot_check_is_refused_with_a_json_rpc_error(
    client: httpx.AsyncClient,
    server: Server,
    signing_key: RSAPrivateKey,
    body: bytes,
    status: int,
    code: int,
    request_id: object,
) -> None:
    response = await client.post("/mcp", content=body, headers=_auth(signing_key))

    assert response.status_code == status
    problem = response.json()
    assert problem["jsonrpc"] == "2.0"
    assert problem["id"] == request_id
    assert problem["error"]["code"] == code
    assert server.bodies == []


@pytest.mark.parametrize(
    "method", ["initialize", "notifications/initialized", "ping", "tools/list", "resources/read"]
)
async def test_other_methods_pass_with_no_scope_and_count_nothing(
    client: httpx.AsyncClient,
    server: Server,
    reporter: UsageReporter,
    keelie: Keelie,
    signing_key: RSAPrivateKey,
    method: str,
) -> None:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method}).encode()

    response = await client.post("/mcp", content=body, headers=_auth(signing_key, ""))
    await reporter.aclose()

    assert response.status_code == 200
    assert server.bodies == [body]
    assert keelie.events == []


async def test_a_get_passes_after_the_token_check(
    client: httpx.AsyncClient, server: Server, signing_key: RSAPrivateKey
) -> None:
    response = await client.get("/mcp", headers=_auth(signing_key, ""))

    assert response.status_code == 200
    assert server.bodies == [b""]


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
async def test_another_method_with_a_tool_call_gets_405(
    client: httpx.AsyncClient, server: Server, signing_key: RSAPrivateKey, method: str
) -> None:
    response = await client.request(
        method, "/mcp", content=_call("get_order"), headers=_auth(signing_key, "")
    )

    assert response.status_code == 405
    assert response.headers["allow"] == "GET, POST, DELETE"
    assert server.bodies == []


@pytest.mark.parametrize(
    ("status", "sse", "counted"), [(200, True, 1), (200, False, 1), (500, False, 0)]
)
async def test_one_event_for_each_tool_call_the_server_accepts(
    client: httpx.AsyncClient,
    server: Server,
    reporter: UsageReporter,
    keelie: Keelie,
    signing_key: RSAPrivateKey,
    status: int,
    sse: bool,
    counted: int,
) -> None:
    server.status, server.sse = status, sse

    response = await client.post("/mcp", content=_call("get_order"), headers=_auth(signing_key))
    await reporter.aclose()

    assert response.status_code == status
    if sse:
        # The stream reaches the client unchanged.
        assert response.text == "data: 1\n\ndata: 2\n\n"
    assert [(e["client_id"], e["capability_key"], e["unit"]) for e in keelie.events] == [
        ("client-1", "get_order", "tool_call")
    ] * counted
    assert all("credits" not in e for e in keelie.events)
