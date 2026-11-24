"""The issuer's signing keys, kept in the process.

The first token fetches the key set: the issuer's discovery document names its
``jwks_uri``, and that document holds the keys. A ``kid`` the cache does not know
fetches once more, then is refused. That is how a rotated key is picked up without
a restart: the first token it signs fetches it.

Once a key set is in hand, at most one fetch a minute, however many unknown
``kid`` values arrive and whether or not the fetch succeeds. A flood of made-up
``kid`` values costs the issuer one request a minute, also while the issuer is
down.

With no key set in hand, every caller waits on one shared fetch and gets its
outcome, a failure too. After a failed fetch, the SDK waits 5 seconds before it
asks the issuer again. A token in that window is refused at once. Each request
to the issuer has a total deadline of 5 seconds.

A fetch that brings no usable signing key, such as ``{"keys": []}``, is a failed
fetch. The keys in hand stay and go on verifying. A set with a usable key
replaces the old set, so a rotation still retires the old keys.

The issuer and the ``jwks_uri`` must be https URLs. Plain http is allowed only
for a loopback host, for local development.

The ``jwks_uri`` from the first discovery is kept for the life of the process.
A discovery document whose ``issuer`` is not the configured one is refused, and
no key is fetched from it (OpenID Connect Discovery 1.0, section 4.3). Each
Provider has its own realm, so each issuer has its own key set: a document of
another realm must never fill this one's.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Literal
from urllib.parse import urlsplit

import httpx
import jwt

from apiable.discovery import LOOPBACK_HOSTS

logger = logging.getLogger(__name__)

# The one algorithm the SDK accepts, in the key set and on the token.
ALGORITHM = "RS256"

# How long the cache refuses a second fetch after one completed. Shorter than any
# token lifetime, so a rotation is never waited out.
REFRESH_INTERVAL_SECONDS = 60.0

# The total deadline of each request to the issuer: connect, send and read.
FETCH_TIMEOUT_SECONDS = 5.0

# With no key set in hand, how long a failed fetch is remembered. A token in this
# window is refused at once, and the issuer is not asked.
COLD_RETRY_SECONDS = 5.0

Status = Literal["connected", "degraded", "offline"]


class UnknownKey(LookupError):
    """No key in the set has this ``kid``, after one refresh."""


class KeysUnavailable(Exception):
    """The key set could not be fetched, and no key set is in hand."""


def secure_url(name: str, value: str) -> str:
    """The value, if it is an https URL with a host and no user. Plain http only on loopback."""
    if not isinstance(value, str):
        raise ValueError(f"{name} is not a URL: {value!r}")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        user = parts.username
    except ValueError as exc:
        raise ValueError(f"{name} is not a URL: {value!r}") from exc
    if not host or not (
        parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK_HOSTS)
    ):
        raise ValueError(f"{name} must be https, or http on a loopback host: {value!r}")
    if user is not None:
        raise ValueError(f"{name} must not carry a user: {value!r}")
    return value


class SigningKeys:
    """The issuer's RS256 signing keys, fetched on first use and refreshed on an unknown ``kid``."""

    def __init__(
        self,
        issuer: str,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        refresh_interval_seconds: float = REFRESH_INTERVAL_SECONDS,
        fetch_timeout_seconds: float = FETCH_TIMEOUT_SECONDS,
    ) -> None:
        self._issuer = secure_url("issuer", issuer).rstrip("/")
        self._client = client
        self._clock = clock
        self._interval = refresh_interval_seconds
        self._timeout = fetch_timeout_seconds
        self._keys: dict[str, jwt.PyJWK] = {}
        self._jwks_uri: str | None = None
        self._fetched_at: float | None = None
        self._refresh_failed = False
        # With no key in hand: when the last fetch failed, and why.
        self._cold_failed_at: float | None = None
        self._cold_error = ""
        # The fetch on its way. Every caller that needs a fetch waits on this one.
        # Made inside the running event loop, so it binds to that loop.
        self._inflight: asyncio.Task[None] | None = None

    async def key(self, kid: str) -> jwt.PyJWK:
        """The key with this id, fetching the set once if it is not there."""
        if kid in self._keys:
            return self._keys[kid]
        if not self._keys and self._cold_window():
            # The last fetch failed a moment ago. Refuse at once: the issuer is
            # not asked again until the window ends.
            logger.warning("apiable.keys_unavailable: %s", self._cold_error)
            raise KeysUnavailable
        task = self._inflight
        if task is not None and (task.done() or task.get_loop() is not asyncio.get_running_loop()):
            task = None
        if task is None and self._may_fetch():
            task = asyncio.get_running_loop().create_task(self._refresh())
            # Retrieve the outcome even when every waiter was cancelled. Otherwise
            # asyncio logs "Task exception was never retrieved" for a failed fetch.
            task.add_done_callback(lambda done: done.cancelled() or done.exception())
            self._inflight = task
        if task is not None:
            # Every caller that finds the cache cold, or its kid missing, waits on
            # the same fetch and gets its outcome. The issuer answers one request,
            # not one for each caller. The shield keeps one caller's cancel from
            # cancelling the fetch of the others.
            await asyncio.shield(task)
        if kid in self._keys:
            return self._keys[kid]
        raise UnknownKey(kid)

    def status(self) -> Status:
        """``offline`` with no key, ``degraded`` if the last fetch failed, else ``connected``."""
        if not self._keys:
            return "offline"
        return "degraded" if self._refresh_failed else "connected"

    def _may_fetch(self) -> bool:
        return self._fetched_at is None or self._clock() - self._fetched_at >= self._interval

    def _cold_window(self) -> bool:
        failed_at = self._cold_failed_at
        return failed_at is not None and self._clock() - failed_at < COLD_RETRY_SECONDS

    async def _refresh(self) -> None:
        try:
            keys = _signing_keys(await self._fetch())
            if not keys:
                # An empty set must not wipe the keys in hand.
                raise ValueError("no signing key")
        except (
            httpx.HTTPError,
            httpx.InvalidURL,
            asyncio.TimeoutError,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:
            if not self._keys:
                # Cold: nothing to verify with. Remember the failure for a few
                # seconds, so that a burst of tokens does not hammer the issuer.
                self._cold_failed_at = self._clock()
                self._cold_error = type(exc).__name__
                logger.warning("apiable.keys_unavailable: %s", self._cold_error)
                raise KeysUnavailable from exc
            # Warm: the keys in hand go on verifying, and the issuer is not asked
            # again for another interval.
            self._fetched_at = self._clock()
            self._refresh_failed = True
            logger.warning("apiable.keys_not_refreshed: %s", type(exc).__name__)
            return
        self._keys = keys
        self._fetched_at = self._clock()
        self._refresh_failed = False
        self._cold_failed_at = None
        logger.info("apiable.keys_loaded kids=%s", sorted(self._keys))

    async def _fetch(self) -> object:
        if self._client is not None:
            return await self._fetch_with(self._client)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await self._fetch_with(client)

    async def _get_json(self, client: httpx.AsyncClient, url: str) -> object:
        """The JSON body at ``url``, within the total deadline. httpx alone times each read."""

        async def get() -> object:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

        return await asyncio.wait_for(get(), self._timeout)

    async def _fetch_with(self, client: httpx.AsyncClient) -> object:
        jwks_uri = self._jwks_uri
        if jwks_uri is None:
            document = await self._get_json(
                client, f"{self._issuer}/.well-known/openid-configuration"
            )
            if not isinstance(document, dict):
                raise TypeError("discovery")
            issuer = document["issuer"]
            if not isinstance(issuer, str) or issuer.rstrip("/") != self._issuer:
                raise ValueError("issuer")
            jwks_uri = document["jwks_uri"]
            if not isinstance(jwks_uri, str):
                raise TypeError("jwks_uri")
            # Never fetch keys over plain http from a host the document names.
            secure_url("jwks_uri", jwks_uri)
        key_set = await self._get_json(client, jwks_uri)
        if not isinstance(key_set, dict):
            raise TypeError("keys")
        self._jwks_uri = jwks_uri
        return key_set["keys"]


def _signing_keys(key_set: object) -> dict[str, jwt.PyJWK]:
    if not isinstance(key_set, list):
        raise TypeError("keys")
    keys: dict[str, jwt.PyJWK] = {}
    for jwk in key_set:
        # The issuer can publish an encryption key beside the signing key. Only an
        # RSA key for signing, with the one algorithm and a kid, verifies a token.
        if (
            not isinstance(jwk, dict)
            or not isinstance(jwk.get("kid"), str)
            or jwk.get("kty") != "RSA"
            or jwk.get("use") not in (None, "sig")
            or jwk.get("alg") not in (None, ALGORITHM)
        ):
            continue
        # Only the public part is read. A key published with its private member `d`
        # by mistake would otherwise load as a private key, which cannot verify.
        public = {name: jwk[name] for name in ("kty", "kid", "n", "e") if name in jwk}
        try:
            keys[jwk["kid"]] = jwt.PyJWK(public, algorithm=ALGORITHM)
        except (jwt.PyJWTError, ValueError):
            # A key the SDK cannot load is skipped. The rest of the set loads.
            logger.warning("apiable.key_skipped kid=%s", jwk["kid"])
    return keys
