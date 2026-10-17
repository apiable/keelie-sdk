"""The issuer and the tokens the tests share, served without a network."""

from __future__ import annotations

import asyncio
import json
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

ISSUER = "https://issuer.example.test/realms/test"
AUDIENCE = "provider-api"
ORG_ID = uuid.UUID("01890000-0000-7000-8000-000000000001")


def private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(kid: str, key: RSAPrivateKey, **extra: str) -> dict[str, str]:
    public: dict[str, str] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update({"kid": kid, "use": "sig", "alg": "RS256", **extra})
    return public


class Issuer:
    """The issuer's discovery document and key set, served without a network.

    ``url`` is the realm. ``says`` is the ``issuer`` its discovery document names:
    the realm itself, unless a test makes it lie.
    """

    def __init__(self, url: str = ISSUER, says: str | None = None) -> None:
        self.url = url
        self.says = url if says is None else says
        self.jwks_uri = f"{url}/protocol/openid-connect/certs"
        self.keys: list[dict[str, str]] = []
        self.jwks_fetches = 0
        self.down = False

    async def handler(self, request: httpx.Request) -> httpx.Response:
        # Yield, as a real fetch does, so that concurrent callers overlap.
        await asyncio.sleep(0.01)
        if self.down:
            return httpx.Response(503)
        if str(request.url) == f"{self.url}/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": self.says, "jwks_uri": self.jwks_uri})
        if str(request.url) == self.jwks_uri:
            self.jwks_fetches += 1
            return httpx.Response(200, json={"keys": self.keys})
        return httpx.Response(404)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def claims(**overrides: object) -> dict[str, object]:
    now = int(time.time())
    payload: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "typ": "Bearer",
        "azp": "client-1",
        "sub": "service-account-user",
        "org_id": str(ORG_ID),
        "scope": "orders:read orders:write",
        "jti": "jti-1",
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def signed_token(key: RSAPrivateKey, kid: str = "sig-1", **overrides: object) -> str:
    return jwt.encode(claims(**overrides), key, algorithm="RS256", headers={"kid": kid})
