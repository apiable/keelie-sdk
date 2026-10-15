"""One codebase serves both adapters: the same token check, through both."""

from __future__ import annotations

import ast
import json
import pathlib
import time
import uuid
from collections.abc import Callable

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from support import ISSUER, private_key, signed_token

import apiable
import apiable.guard
from apiable import McpGuard, ProtectedResourceMetadata, TokenGuard, TokenVerifier, UsageReporter
from apiable.discovery import ASGIApp, Receive, Scope, Send
from apiable.guard import CLAIMS_KEY
from apiable.tokens import Claims

RESOURCE = "https://api.example.test/api"
METADATA_URL = "https://api.example.test/.well-known/oauth-protected-resource/api"
TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

Adapter = Callable[[ASGIApp, TokenVerifier], ASGIApp]


async def _provider(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def _rest(app: ASGIApp, verifier: TokenVerifier) -> ASGIApp:
    return TokenGuard(app, verifier, ProtectedResourceMetadata(RESOURCE, ISSUER))


def _mcp(app: ASGIApp, verifier: TokenVerifier) -> ASGIApp:
    reporter = UsageReporter(
        httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    )
    return McpGuard(
        app, verifier, ProtectedResourceMetadata(RESOURCE, ISSUER), {}, reporter=reporter
    )


ADAPTERS = pytest.mark.parametrize("adapter", [_rest, _mcp], ids=["rest", "mcp"])


async def _post(adapter: ASGIApp, authorization: str | None) -> httpx.Response:
    headers = {} if authorization is None else {"Authorization": authorization}
    transport = httpx.ASGITransport(app=adapter)
    async with httpx.AsyncClient(transport=transport, base_url="https://api.example.test") as c:
        return await c.post("/api", content=json.dumps(TOOLS_LIST), headers=headers)


@ADAPTERS
@pytest.mark.parametrize(
    ("make_token", "status", "challenge"),
    [
        (lambda k: signed_token(k), 200, None),
        (None, 401, f'Bearer resource_metadata="{METADATA_URL}"'),
        (lambda k: signed_token(k, exp=int(time.time()) - 31), 401, "invalid_token"),
        (lambda k: signed_token(k, org_id=str(uuid.uuid4())), 401, "invalid_token"),
        (lambda k: signed_token(k, aud="another-api"), 401, "invalid_token"),
        (lambda _: signed_token(private_key()), 401, "invalid_token"),
        (lambda _: "not-a-token", 401, "invalid_token"),
    ],
)
async def test_both_adapters_answer_each_token_the_same(
    adapter: Adapter,
    verifier: TokenVerifier,
    signing_key: RSAPrivateKey,
    make_token: Callable[[RSAPrivateKey], str] | None,
    status: int,
    challenge: str | None,
) -> None:
    authorization = None if make_token is None else f"Bearer {make_token(signing_key)}"

    response = await _post(adapter(_provider, verifier), authorization)

    assert response.status_code == status
    if challenge == "invalid_token":
        # One refusal for every reason: the reason goes to the log only.
        assert response.headers["www-authenticate"] == (
            f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
        )
        assert response.content == b""
    elif challenge is not None:
        assert response.headers["www-authenticate"] == challenge
    else:
        assert "www-authenticate" not in response.headers


@ADAPTERS
async def test_both_adapters_check_the_token_through_the_shared_core(
    adapter: Adapter,
    verifier: TokenVerifier,
    signing_key: RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Claims] = []
    core = apiable.guard.authenticate

    async def spy(verifier: TokenVerifier, scope: Scope) -> Claims:
        claims = await core(verifier, scope)
        calls.append(claims)
        return claims

    monkeypatch.setattr(apiable.guard, "authenticate", spy)

    response = await _post(adapter(_provider, verifier), f"Bearer {signed_token(signing_key)}")

    assert response.status_code == 200
    assert [c.azp for c in calls] == ["client-1"]


@ADAPTERS
async def test_a_path_outside_the_resource_passes_both_adapters_untouched(
    adapter: Adapter, verifier: TokenVerifier
) -> None:
    bodies: list[bytes] = []

    async def provider(scope: Scope, receive: Receive, send: Send) -> None:
        bodies.append(bytes((await receive())["body"]))  # type: ignore[arg-type]
        await _provider(scope, receive, send)

    transport = httpx.ASGITransport(app=adapter(provider, verifier))
    async with httpx.AsyncClient(transport=transport, base_url="https://api.example.test") as c:
        response = await c.post("/health", content=b"{not json")

    assert response.status_code == 200
    assert bodies == [b"{not json"]


async def test_the_rest_adapter_gives_the_claims_to_the_route(
    verifier: TokenVerifier, signing_key: RSAPrivateKey
) -> None:
    seen: list[Scope] = []

    async def route(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope)
        await _provider(scope, receive, send)

    guard = _rest(route, verifier)
    response = await _post(
        _with_state(guard, {"from_lifespan": 1}), f"Bearer {signed_token(signing_key)}"
    )

    assert response.status_code == 200
    state = seen[0]["state"]
    assert isinstance(state, dict)
    assert state[CLAIMS_KEY].azp == "client-1"
    # The server's lifespan state stays.
    assert state["from_lifespan"] == 1


def _with_state(app: ASGIApp, state: dict[str, object]) -> ASGIApp:
    """``app``, called with the state that a server such as uvicorn puts in the scope."""

    async def call(scope: Scope, receive: Receive, send: Send) -> None:
        await app({**scope, "state": dict(state)}, receive, send)

    return call


# The modules that may verify a token: the verifier, its key set, and the core.
_CORE = {"tokens.py", "keys.py", "guard.py"}


def test_no_module_outside_the_core_holds_its_own_token_check() -> None:
    package = pathlib.Path(apiable.__file__).parent
    for path in sorted(package.glob("*.py")):
        if path.name in _CORE:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = ".".join(filter(None, ["apiable" if node.level else "", node.module]))
                names = [module] + [f"{module}.{alias.name}" for alias in node.names]
            else:
                names = []
            for name in names:
                assert name.split(".")[0] != "jwt", f"{path.name} imports {name}"
                assert not name.startswith("apiable.keys"), f"{path.name} imports {name}"
            if isinstance(node, ast.Attribute):
                assert node.attr != "verify", f"{path.name} calls .verify itself"
