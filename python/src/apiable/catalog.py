"""Serve your AI Catalog from your own domain, at ``/.well-known/ai-catalog.json``.

keelie builds the catalog from your published plans. :class:`AiCatalog` fetches
it from keelie with your credential, keeps it for 60 seconds, and serves it with
no token. A plan you publish shows here within 60 seconds.

The SDK does not change the document. It keeps no copy past 60 seconds: if keelie
does not answer when the copy is old, the answer is ``503``, not an old catalog.
After a failure, it asks keelie again after 10 seconds, not on each request.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

import httpx

from apiable.discovery import CATALOG_PATH, ASGIApp, Receive, Scope, Send, respond

logger = logging.getLogger(__name__)

# The one place that names keelie's catalog endpoint.
KEELIE_PATH = "/ai-catalog"

MEDIA_TYPE = b"application/ai-catalog+json"
CACHE_SECONDS = 60.0
RETRY_SECONDS = 10.0


class AiCatalog:
    """Serves the catalog at ``/.well-known/ai-catalog.json``. Other requests pass untouched.

    ``client`` carries keelie's base URL and the auth of a credential that may
    read products, as for :class:`~apiable.UsageReporter`. It does not close it.

    It is ASGI middleware. In FastAPI or Starlette::

        app.add_middleware(AiCatalog, client=client)

    The token guards let this path pass with no token, so the order of the
    middleware does not matter.
    """

    def __init__(
        self,
        app: ASGIApp,
        client: httpx.AsyncClient,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._app = app
        self._client = client
        self._clock = clock
        self._body: bytes | None = None
        self._fetched_at = 0.0
        self._failed_at: float | None = None
        # Made inside the running event loop, on the first request: on Python 3.9
        # a lock made outside it binds to a different loop.
        self._lock: asyncio.Lock | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("path") != CATALOG_PATH
            or scope.get("method") not in ("GET", "HEAD")
        ):
            await self._app(scope, receive, send)
            return
        head = scope["method"] == "HEAD"
        body = await self._catalog()
        if body is None:
            headers = [(b"retry-after", b"10"), (b"cache-control", b"no-store")]
            await respond(send, 503, headers, b"", head=head)
            return
        headers = [(b"content-type", MEDIA_TYPE), (b"cache-control", b"max-age=60")]
        await respond(send, 200, headers, body, head=head)

    async def _catalog(self) -> bytes | None:
        """The catalog, fetched again when the copy is 60 seconds old. None if keelie fails."""
        if self._settled():
            return self._body
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            # One fetch for many requests at once: the others read what it got,
            # or its failure.
            if self._settled():
                return self._body
            self._body = None
            try:
                response = await self._client.get(KEELIE_PATH)
            except httpx.HTTPError as exc:
                logger.warning("apiable.catalog_fetch_failed error=%s", type(exc).__name__)
                self._failed_at = self._clock()
                return None
            if response.status_code != 200:
                logger.warning("apiable.catalog_fetch_failed status=%s", response.status_code)
                self._failed_at = self._clock()
                return None
            self._body = response.content
            self._fetched_at = self._clock()
            self._failed_at = None
            return self._body

    def _settled(self) -> bool:
        """True while the copy is fresh, or while a failure is recent: no fetch is due."""
        now = self._clock()
        if self._failed_at is not None:
            return now - self._failed_at < RETRY_SECONDS
        return self._body is not None and now - self._fetched_at < CACHE_SECONDS
