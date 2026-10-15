"""The one token check, and the REST adapter on it.

Every adapter of the SDK checks a token through :func:`authenticate`, here, and
through nothing else. An adapter answers a refused token through
:class:`Guard`, so every adapter refuses it in the same way: ``401``, an empty
body, and ``WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."``.
The answer is the same for every reason. The reason goes to your log only.

Two adapters stand on this core:

- :class:`TokenGuard`, for a REST API, here.
- :class:`~apiable.McpGuard`, for a Streamable HTTP MCP server, in ``mcp``.
"""

from __future__ import annotations

from apiable.discovery import (
    ASGIApp,
    MissingTokenChallenge,
    ProtectedResourceMetadata,
    Receive,
    Scope,
    Send,
    bearer_token,
    guarded,
    respond,
)
from apiable.tokens import Claims, TokenRejected, TokenVerifier

# The key of the verified claims in ``scope["state"]``. In FastAPI or
# Starlette, a route reads them as ``request.state.apiable_claims``.
CLAIMS_KEY = "apiable_claims"


async def authenticate(verifier: TokenVerifier, scope: Scope) -> Claims:
    """The claims of the request's Bearer token, or :class:`~apiable.TokenRejected`."""
    token = bearer_token(scope)
    if token is None:
        raise TokenRejected("malformed")
    return await verifier.verify(token)


class Guard:
    """The part every adapter shares. An adapter adds only what it does with the claims.

    It is ASGI middleware. It wraps :class:`~apiable.MissingTokenChallenge`, so
    one mount line serves the metadata, refuses a request with no token, and
    refuses a token that does not verify. Paths outside ``resource``, a CORS
    preflight (``OPTIONS``) and every request that is not HTTP pass untouched.
    """

    def __init__(
        self, app: ASGIApp, verifier: TokenVerifier, metadata: ProtectedResourceMetadata
    ) -> None:
        self._app = app
        self._verifier = verifier
        self._metadata = metadata
        self._refusal = metadata.challenge("invalid_token").encode()
        self._outer = MissingTokenChallenge(self._check, metadata)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._outer(scope, receive, send)

    async def _check(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not guarded(scope, self._metadata):
            await self._app(scope, receive, send)
            return
        try:
            claims = await authenticate(self._verifier, scope)
        except TokenRejected:
            await respond(send, 401, [(b"www-authenticate", self._refusal)], b"")
            return
        await self.handle(claims, scope, receive, send)

    async def handle(self, claims: Claims, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve a request whose token verified."""
        raise NotImplementedError


class TokenGuard(Guard):
    """The REST adapter: checks the token, and gives the claims to your routes.

    In FastAPI or Starlette::

        app.add_middleware(TokenGuard, verifier=verifier, metadata=metadata)

    A route reads the claims as ``request.state.apiable_claims``.

    It does not check the scope. Middleware runs before the router, so it cannot
    see the route template your framework matches. Each route must call
    :meth:`~apiable.ScopeMap.check` with its own method and template. A route
    that does not call it is authenticated, but it has no scope check.
    """

    async def handle(self, claims: Claims, scope: Scope, receive: Receive, send: Send) -> None:
        state = scope.setdefault("state", {})
        state[CLAIMS_KEY] = claims  # type: ignore[index]
        await self._app(scope, receive, send)
