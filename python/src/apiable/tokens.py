"""Verify an access token inside your own process.

The SDK never asks Apiable whether a token is good. It checks the signature
against the issuer's key set (see ``keys``) and the claims against what you
configured. The checks run in this order, and the first that fails refuses the
token:

1. The token parses, its ``alg`` is ``RS256`` and it names a ``kid``. A token
   that says ``none`` or ``HS256`` is refused before any key is fetched.
2. The key with that ``kid`` is in the issuer's key set.
3. The signature, ``exp`` (required), ``nbf``, ``iat``, ``iss`` and ``aud``.
4. ``azp`` names the client, and ``org_id`` is your own org id. In a shared
   realm, every Provider's tokens share one issuer and one key set; ``org_id``
   is what tells them apart.
5. ``typ`` is ``Bearer``. An ID token is signed with the same key.

Every refusal raises :class:`TokenRejected`. Its ``reason`` is for your log, not
for the caller: a caller must not learn "expired" from "wrong key".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

import jwt

from apiable.keys import ALGORITHM, KeysUnavailable, SigningKeys, UnknownKey

logger = logging.getLogger(__name__)

TOKEN_TYPE = "Bearer"  # noqa: S105 - a token type, not a secret

# Clock skew a token is forgiven.
LEEWAY_SECONDS = 30

Reason = Literal[
    "malformed",
    "algorithm",
    "kid",
    "keys_unavailable",
    "signature",
    "expired",
    "not_yet_valid",
    "issuer",
    "audience",
    "claims",
    "org",
    "typ",
]


class TokenRejected(Exception):
    """The token does not verify. ``reason`` is for the log."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason)
        self.reason: Reason = reason


@dataclass(frozen=True)
class Claims:
    """The claims of a verified token that the SDK reads."""

    # The client the token was issued to: the credential. ``sub`` names the
    # issuer's own service-account user and is ignored.
    azp: str
    org_id: UUID
    scopes: frozenset[str]
    jti: str | None


class TokenVerifier:
    """Verifies the tokens of one issuer, for one audience and one org."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        org_id: UUID | str,
        *,
        keys: SigningKeys | None = None,
        leeway_seconds: int = LEEWAY_SECONDS,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._org_id = UUID(str(org_id))
        self._keys = keys if keys is not None else SigningKeys(issuer)
        self._leeway = leeway_seconds

    async def verify(self, token: str) -> Claims:
        """The claims of the token, or :class:`TokenRejected` with the reason."""
        try:
            claims = await self._verify(token)
        except TokenRejected as exc:
            logger.info("apiable.token_rejected reason=%s", exc.reason)
            raise
        return claims

    async def _verify(self, token: str) -> Claims:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenRejected("malformed") from exc
        if header.get("alg") != ALGORITHM:
            raise TokenRejected("algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenRejected("kid")

        try:
            key = await self._keys.key(kid)
        except UnknownKey as exc:
            raise TokenRejected("kid") from exc
        except KeysUnavailable as exc:
            raise TokenRejected("keys_unavailable") from exc

        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={"require": ["exp"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenRejected("expired") from exc
        except (jwt.ImmatureSignatureError, jwt.InvalidIssuedAtError) as exc:
            raise TokenRejected("not_yet_valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenRejected("issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenRejected("audience") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenRejected("audience" if exc.claim == "aud" else "claims") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenRejected("signature") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenRejected("malformed") from exc

        azp = payload.get("azp")
        scope = payload.get("scope", "")
        jti = payload.get("jti")
        try:
            org_id = UUID(payload["org_id"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise TokenRejected("claims") from exc
        if (
            not isinstance(azp, str)
            or not azp
            or not isinstance(scope, str)
            or not isinstance(jti, (str, type(None)))
        ):
            raise TokenRejected("claims")
        if org_id != self._org_id:
            raise TokenRejected("org")
        if payload.get("typ") != TOKEN_TYPE:
            raise TokenRejected("typ")
        return Claims(azp=azp, org_id=org_id, scopes=frozenset(scope.split()), jti=jti)
