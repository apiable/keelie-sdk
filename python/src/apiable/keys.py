"""The issuer's signing keys, kept in the process.

The first token fetches the key set: the issuer's discovery document names its
``jwks_uri``, and that document holds the keys. A ``kid`` the cache does not know
fetches once more, then is refused. That is how a rotated key is picked up without
a restart: the first token it signs fetches it.

Once a key set is in hand, at most one fetch a minute, however many unknown
``kid`` values arrive and whether or not the fetch succeeds. A flood of made-up
``kid`` values costs the issuer one request a minute, also while the issuer is
down. With no key set in hand, a failed fetch caches nothing, and the next caller
tries again.

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

import httpx
import jwt

logger = logging.getLogger(__name__)

# The one algorithm the SDK accepts, in the key set and on the token.
ALGORITHM = "RS256"

# How long the cache refuses a second fetch after one completed. Shorter than any
# token lifetime, so a rotation is never waited out.
REFRESH_INTERVAL_SECONDS = 60.0

FETCH_TIMEOUT_SECONDS = 5.0


class UnknownKey(LookupError):
    """No key in the set has this ``kid``, after one refresh."""


class KeysUnavailable(Exception):
    """The key set could not be fetched, and no key set is in hand."""


class SigningKeys:
    """The issuer's RS256 signing keys, fetched on first use and refreshed on an unknown ``kid``."""

    def __init__(
        self,
        issuer: str,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        refresh_interval_seconds: float = REFRESH_INTERVAL_SECONDS,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client = client
        self._clock = clock
        self._interval = refresh_interval_seconds
        self._keys: dict[str, jwt.PyJWK] = {}
        self._jwks_uri: str | None = None
        self._fetched_at: float | None = None
        # Made on first use, inside the running event loop: on Python 3.9 a lock
        # made outside it binds to a different loop.
        self._lock: asyncio.Lock | None = None

    async def key(self, kid: str) -> jwt.PyJWK:
        """The key with this id, fetching the set once if it is not there."""
        if kid in self._keys:
            return self._keys[kid]
        if self._lock is None:
            self._lock = asyncio.Lock()
        # Every caller that finds the cache cold, or its kid missing, waits on the
        # same fetch. The issuer answers one request, not one for each caller.
        async with self._lock:
            if kid not in self._keys and self._may_fetch():
                await self._refresh()
        if kid in self._keys:
            return self._keys[kid]
        raise UnknownKey(kid)

    def _may_fetch(self) -> bool:
        return self._fetched_at is None or self._clock() - self._fetched_at >= self._interval

    async def _refresh(self) -> None:
        try:
            keys = _signing_keys(await self._fetch())
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, KeyError, TypeError) as exc:
            if self._fetched_at is None:
                # Cold: nothing to verify with. Nothing is cached, so the next
                # caller tries again.
                logger.warning("apiable.keys_unavailable: %s", type(exc).__name__)
                raise KeysUnavailable from exc
            # Warm: the keys in hand go on verifying, and the issuer is not asked
            # again for another interval.
            self._fetched_at = self._clock()
            logger.warning("apiable.keys_not_refreshed: %s", type(exc).__name__)
            return
        self._keys = keys
        self._fetched_at = self._clock()
        logger.info("apiable.keys_loaded kids=%s", sorted(self._keys))

    async def _fetch(self) -> object:
        if self._client is not None:
            return await self._fetch_with(self._client)
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT_SECONDS) as client:
            return await self._fetch_with(client)

    async def _fetch_with(self, client: httpx.AsyncClient) -> object:
        jwks_uri = self._jwks_uri
        if jwks_uri is None:
            response = await client.get(f"{self._issuer}/.well-known/openid-configuration")
            response.raise_for_status()
            document = response.json()
            issuer = document["issuer"]
            if not isinstance(issuer, str) or issuer.rstrip("/") != self._issuer:
                raise ValueError("issuer")
            jwks_uri = document["jwks_uri"]
            if not isinstance(jwks_uri, str):
                raise TypeError("jwks_uri")
        response = await client.get(jwks_uri)
        response.raise_for_status()
        key_set = response.json()["keys"]
        self._jwks_uri = jwks_uri
        return key_set


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
        try:
            keys[jwk["kid"]] = jwt.PyJWK(jwk, algorithm=ALGORITHM)
        except (jwt.PyJWTError, ValueError):
            # A key the SDK cannot load is skipped. The rest of the set loads.
            logger.warning("apiable.key_skipped kid=%s", jwk["kid"])
    return keys
