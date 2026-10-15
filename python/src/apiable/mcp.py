"""The adapter for a Streamable HTTP MCP server.

:class:`McpGuard` wraps your MCP server's ASGI app. It checks the token with the
same core as the REST adapter (see ``guard``), checks the scope of each tool
call, and reports one usage event for each tool call the server accepts.

What it checks on a request whose token verified:

- A ``POST`` body is read in full, up to ``max_body_bytes``, and handed on to
  your server unchanged. The method and the tool name come from the body only,
  never from the ``Mcp-Method`` or ``Mcp-Name`` header.
- A ``tools/call`` needs the scope you mapped to its tool. A tool that is not in
  the map is refused. Add every tool that a token may call.
- Every other method passes with no scope check: ``initialize``,
  ``notifications/*``, ``ping``, ``tools/list``, and also ``resources/*`` and
  ``prompts/*``. Apiable sells tools, not resources or prompts.
- ``GET`` and ``DELETE`` pass, and so does a CORS preflight (``OPTIONS``).

Every refusal is a JSON-RPC error:

- ``400``, ``-32700``: the body is not UTF-8 JSON, or it is nested too deeply.
- ``400``, ``-32600``: the body is an array, is not an object, has a key twice,
  or is a ``tools/call`` with no ``id``. A batch is refused on purpose: MCP
  removed batches in 2025-06-18, so a 2025-03-26 client that batches is cut.
- ``400``, ``-32602``: a ``tools/call`` whose ``params.name`` is not a string.
- ``413``, ``-32600``: the body is larger than ``max_body_bytes``.
- ``403``, ``-31001``, with ``WWW-Authenticate: Bearer error="insufficient_scope"``:
  the token does not carry the tool's scope. The answer does not name the
  scope, on purpose: an unmapped tool and an unscoped tool look the same, so the
  answer does not show the map.

The usage event is recorded when your server starts a ``2xx`` response, not at
the end of its body, so a ``text/event-stream`` reply streams through
unbuffered. The event carries no ``credits``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping

from apiable.discovery import (
    ASGIApp,
    Message,
    ProtectedResourceMetadata,
    Receive,
    Scope,
    Send,
    respond,
)
from apiable.guard import Guard
from apiable.scopes import InsufficientScope, ScopeMap
from apiable.tokens import Claims, TokenVerifier
from apiable.usage import UsageReporter

logger = logging.getLogger(__name__)

# The method of a tool call. It is also the method half of each key in the
# adapter's ScopeMap: ``("tools/call", <tool name>)``.
TOOLS_CALL = "tools/call"

MAX_BODY_BYTES = 4 * 1024 * 1024

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
# An application code: MCP keeps -32000 to -32099 for itself.
INSUFFICIENT_SCOPE = -31001


class _DuplicateKey(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # Two parsers can pick different values for a key given twice: refuse it.
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


class McpGuard(Guard):
    """Checks the token and the tool's scope, and reports each tool call.

    ``tools`` maps each tool name to the one scope it requires, such as
    ``{"get_order": "orders:read"}``. ``reporter`` is the process's one
    :class:`~apiable.UsageReporter`.

    Give the MCP endpoint itself as the ``resource`` of ``metadata``: every
    ``POST`` under it is read as JSON-RPC.

    In FastAPI or Starlette, with the MCP app at ``/mcp``::

        metadata = ProtectedResourceMetadata(
            "https://api.example.com/mcp", "https://issuer.example.com/realms/example"
        )
        app.add_middleware(
            McpGuard, verifier=verifier, metadata=metadata, tools=tools, reporter=reporter
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        verifier: TokenVerifier,
        metadata: ProtectedResourceMetadata,
        tools: Mapping[str, str],
        reporter: UsageReporter,
        *,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        super().__init__(app, verifier, metadata)
        self._scopes = ScopeMap({(TOOLS_CALL, name): scope for name, scope in tools.items()})
        self._reporter = reporter
        self._max_body_bytes = max_body_bytes
        self._scope_refusal = metadata.challenge("insufficient_scope").encode()

    async def handle(self, claims: Claims, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["method"] != "POST":
            await self._app(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return  # the client went away
            chunk = message.get("body", b"")
            if isinstance(chunk, (bytes, bytearray)):
                body.extend(chunk)
            if len(body) > self._max_body_bytes:
                await _error(send, 413, None, INVALID_REQUEST, "Request body too large")
                return
            if not message.get("more_body", False):
                break

        try:
            request = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except _DuplicateKey:
            await _error(send, 400, None, INVALID_REQUEST, "Invalid Request")
            return
        except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
            await _error(send, 400, None, PARSE_ERROR, "Parse error")
            return
        if not isinstance(request, dict):
            await _error(send, 400, None, INVALID_REQUEST, "Invalid Request")
            return

        tool = None
        if request.get("method") == TOOLS_CALL:
            request_id = request.get("id")
            if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
                await _error(send, 400, None, INVALID_REQUEST, "Invalid Request")
                return
            params = request.get("params")
            tool = params.get("name") if isinstance(params, dict) else None
            if not isinstance(tool, str):
                await _error(send, 400, request_id, INVALID_PARAMS, "Invalid params")
                return
            try:
                self._scopes.check(claims, TOOLS_CALL, tool)
            except InsufficientScope:
                await _error(
                    send,
                    403,
                    request_id,
                    INSUFFICIENT_SCOPE,
                    "Insufficient scope",
                    [(b"www-authenticate", self._scope_refusal)],
                )
                return

        await self._app(scope, _replay(bytes(body), receive), self._count(send, claims, tool))

    def _count(self, send: Send, claims: Claims, tool: str | None) -> Send:
        """``send``, which records one event when a tool call's response starts with 2xx."""
        if tool is None:
            return send

        async def counted(message: Message) -> None:
            if message["type"] == "http.response.start":
                status = message.get("status")
                if isinstance(status, int) and 200 <= status < 300:
                    self._reporter.record(claims.azp, tool, unit="tool_call")
            await send(message)

        return counted


def _replay(body: bytes, receive: Receive) -> Receive:
    """``receive``, which gives the body that was read, then the client's next message."""
    given = False

    async def replay() -> Message:
        nonlocal given
        if given:
            return await receive()
        given = True
        return {"type": "http.request", "body": body, "more_body": False}

    return replay


async def _error(
    send: Send,
    status: int,
    request_id: object,
    code: int,
    message: str,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    logger.info("apiable.mcp_refused status=%d code=%d", status, code)
    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        separators=(",", ":"),
    ).encode()
    await respond(send, status, [*(headers or []), (b"content-type", b"application/json")], body)
