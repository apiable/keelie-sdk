"""Tell an agent where to get a token for your API.

Two standard pieces, served from your own domain:

- The protected resource metadata (RFC 9728). It names your API and the one
  issuer that mints tokens for it. An agent reads it at the well-known address
  of your API. For ``https://api.example.com/mcp`` that is
  ``https://api.example.com/.well-known/oauth-protected-resource/mcp``.
- A ``401`` with ``WWW-Authenticate: Bearer resource_metadata="..."`` on a
  request that carries no token (RFC 6750, RFC 9728 section 5). An agent finds
  the metadata from this refusal. It does not read the header on a ``200``.

The issuer serves its own authorization server metadata (RFC 8414). The SDK
does not copy it: it names the issuer, and the agent reads the issuer.

:class:`MissingTokenChallenge` checks that a token is present. It does not
check that the token is good. Verify every token with
:class:`~apiable.TokenVerifier`, and answer a refused token with ``401`` and
``ProtectedResourceMetadata.challenge("invalid_token")``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from urllib.parse import urlsplit

WELL_KNOWN = "/.well-known/oauth-protected-resource"

# Where an agent looks for the AI Catalog of a domain, and the media type of each
# path. ARD v0.91 reads ``ard.json`` and names no media type for it. The ai-catalog
# specification reads ``ai-catalog.json``, and an MCP proposal points there. Both
# serve one body. A GET or a HEAD of either needs no token, but only once
# :class:`~apiable.catalog.AiCatalog` serves it. This map is the one list of those
# paths: the guards and the catalog both read it.
ARD_PATH = "/.well-known/ard.json"
CATALOG_PATH = "/.well-known/ai-catalog.json"
CATALOG_MEDIA_TYPES = {
    ARD_PATH: b"application/json",
    CATALOG_PATH: b"application/ai-catalog+json",
}

Scope = MutableMapping[str, object]
Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# Printable ASCII with no space, quote or backslash: the URL goes inside a
# quoted string of the header, as it is.
_URL = re.compile(r"[!#-\[\]-~]+")


def _https_url(name: str, value: str) -> str:
    """The value, if it is an https URL with a host and no query or fragment.

    The scheme and the host must be lowercase: an uppercase one is refused, not
    folded. keelie stores your ``resource`` with the same rule and puts it into
    ``aud`` exactly, so the value here and the ``aud`` of a token compare equal.
    """
    if not isinstance(value, str) or not _URL.fullmatch(value):
        raise ValueError(f"{name} is not a URL: {value!r}")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.query
        or parts.fragment
        or (parts.path not in ("", "/") and parts.path.endswith("/"))
    ):
        raise ValueError(
            f"{name} must be https, with a host, no user, query, fragment or final slash: {value!r}"
        )
    parts.port  # noqa: B018 - raises ValueError for a port that is not a number
    # `urlsplit` lowercases the scheme, so read the text as it was written.
    if not value.startswith("https://") or parts.netloc != parts.netloc.lower():
        raise ValueError(f"{name} must have a lowercase scheme and host: {value!r}")
    return value


class ProtectedResourceMetadata:
    """The RFC 9728 metadata of your API, and the challenge that points to it.

    ``resource`` is the URL an agent types for your API, exactly, path included.
    The metadata repeats it as it is. ``authorization_server`` is the issuer,
    the same value you give :class:`~apiable.TokenVerifier`. It is one issuer:
    an agent uses the first and does not try a second.

    ``scopes_supported`` is published only if you give it.
    """

    def __init__(
        self,
        resource: str,
        authorization_server: str,
        *,
        scopes_supported: Iterable[str] | None = None,
    ) -> None:
        self.resource = _https_url("resource", resource)
        issuer = _https_url("authorization_server", authorization_server)
        parts = urlsplit(self.resource)
        # The well-known name goes between the host and the path (RFC 9728 section 3.1).
        self._prefix = "" if parts.path in ("", "/") else parts.path.rstrip("/")
        self.path = WELL_KNOWN + self._prefix
        # From the configuration, never from the request's Host.
        self.url = f"{parts.scheme}://{parts.netloc}{self.path}"
        document: dict[str, object] = {
            "resource": self.resource,
            "authorization_servers": [issuer],
            "bearer_methods_supported": ["header"],
        }
        if scopes_supported is not None:
            if isinstance(scopes_supported, str):
                raise ValueError(f"give a list of scopes, not one string: {scopes_supported!r}")
            scopes = list(scopes_supported)
            if not all(isinstance(s, str) and s.split() == [s] for s in scopes):
                raise ValueError(f"not one scope each: {scopes!r}")
            document["scopes_supported"] = scopes
        self.document = json.dumps(document, separators=(",", ":")).encode()
        # Set by :class:`~apiable.catalog.AiCatalog` when it is made with this
        # metadata. Until then the catalog paths are guarded like any other.
        self.ai_catalog = False

    def challenge(self, error: str | None = None) -> str:
        """The ``WWW-Authenticate`` value. Give ``error="invalid_token"`` for a refused token."""
        if error is None:
            return f'Bearer resource_metadata="{self.url}"'
        if not re.fullmatch(r"[a-z_]+", error):
            raise ValueError(f"not an RFC 6750 error code: {error!r}")
        return f'Bearer error="{error}", resource_metadata="{self.url}"'

    def protects(self, path: str) -> bool:
        """True for the path of ``resource`` and every path below it."""
        return not self._prefix or path == self._prefix or path.startswith(self._prefix + "/")


class MissingTokenChallenge:
    """Refuses a request with no Bearer token. Checks presence only: not authentication.

    The refusal is a 401 that names the metadata. A request that carries any
    Bearer token goes on to your app, which must verify it with
    :class:`~apiable.TokenVerifier`.

    It is ASGI middleware. In FastAPI or Starlette::

        metadata = ProtectedResourceMetadata(
            "https://api.example.com/mcp", "https://issuer.example.com/realms/example"
        )
        app.add_middleware(MissingTokenChallenge, metadata=metadata)

    It also serves the metadata, at ``metadata.path``, with no token. Every
    other path outside ``resource`` passes untouched, and so do a GET or a HEAD
    of the AI Catalog, at either of its paths, when
    :class:`~apiable.catalog.AiCatalog` serves it, a CORS preflight
    (``OPTIONS``) and every request that is not HTTP, such as a WebSocket.

    It compares the path the app receives with the path in ``resource``. Mount
    it where those two agree: behind a proxy that strips a prefix, they do not.
    """

    def __init__(self, app: ASGIApp, metadata: ProtectedResourceMetadata) -> None:
        self._app = app
        self._metadata = metadata
        self._challenge = metadata.challenge().encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        path = scope["path"]
        if path == self._metadata.path and scope["method"] in ("GET", "HEAD"):
            # Before the token check: with a resource at the root, the metadata
            # is under it, and the agent reads it with no token.
            await respond(
                send,
                200,
                [(b"content-type", b"application/json")],
                self._metadata.document,
                head=scope["method"] == "HEAD",
            )
            return
        if guarded(scope, self._metadata) and bearer_token(scope) is None:
            await respond(send, 401, [(b"www-authenticate", self._challenge)], b"")
            return
        await self._app(scope, receive, send)


async def respond(
    send: Send, status: int, headers: list[tuple[bytes, bytes]], body: bytes, *, head: bool = False
) -> None:
    headers = [*headers, (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": b"" if head else body})


def guarded(scope: Scope, metadata: ProtectedResourceMetadata) -> bool:
    """True for an HTTP request under ``resource`` that must carry a token.

    A CORS preflight (``OPTIONS``), every path outside ``resource`` and every
    request that is not HTTP pass untouched. So does a GET or a HEAD of the
    metadata, and of the AI Catalog at either of its paths when
    :class:`~apiable.catalog.AiCatalog` serves it. Any other method on those
    paths needs a token.
    """
    path = scope.get("path")
    method = scope.get("method")
    if method in ("GET", "HEAD") and (
        path == metadata.path or (metadata.ai_catalog and path in CATALOG_MEDIA_TYPES)
    ):
        return False
    return (
        scope["type"] == "http"
        and method != "OPTIONS"
        and isinstance(path, str)
        and metadata.protects(path)
    )


def bearer_token(scope: Scope) -> str | None:
    """The Bearer token in the Authorization header, or None. The token is not checked."""
    headers = scope.get("headers") or []
    for name, value in headers:  # ASGI: an iterable of (name, value) byte pairs
        if name == b"authorization":
            scheme, _, token = value.decode("latin-1").strip().partition(" ")
            token = token.strip()
            return token if scheme.lower() == "bearer" and token else None
    return None
