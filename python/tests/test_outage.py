"""keelie is unreachable for 20 minutes, and Consumers call the Provider's API.

The token carries the decision. keelie sets its lifetime from the Consumer's
balance when it mints it. The SDK serves every call while a token lives, and
refuses when it expires. It asks keelie for nothing on the way.
"""

from __future__ import annotations

import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from support import ISSUER, ORG_ID, Clock, Issuer, signed_token

from apiable import ProtectedResourceMetadata, TokenGuard, TokenVerifier
from apiable.discovery import Receive, Scope, Send
from apiable.keys import SigningKeys

RESOURCE = "https://api.example.test/api"


async def _provider(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def _expires_in(seconds: int) -> int:
    return int(time.time()) + seconds


# What each Consumer holds when it calls, 20 minutes into the outage. A token
# expired more than the 30 seconds of leeway ago is refused. From the SDK's view
# there are three cases: a live token, an expired token, and no token.
CONSUMERS = [
    # A large balance gives the plan's full lifetime.
    ("large balance", lambda: _expires_in(3600), 200),
    # The balance reaches zero during the outage: served while the token lives ...
    ("balance reaches zero, token alive", lambda: _expires_in(120), 200),
    # ... and refused once it expires.
    ("balance reaches zero, token expired", lambda: _expires_in(-31), 401),
    # Delinquent before the outage: a short token, expired by now.
    ("delinquent", lambda: _expires_in(-600), 401),
    # Never seen: no token at all.
    ("never seen", None, 401),
]


@pytest.mark.parametrize(("consumer", "exp", "status"), CONSUMERS, ids=[c[0] for c in CONSUMERS])
async def test_consumers_during_a_20_minute_outage(
    issuer: Issuer,
    clock: Clock,
    signing_key: RSAPrivateKey,
    consumer: str,
    exp: object,
    status: int,
) -> None:
    # The audience is the resource: keelie writes the Provider's API address into ``aud``.
    keys = SigningKeys(
        ISSUER, client=httpx.AsyncClient(transport=httpx.MockTransport(issuer.handler)), clock=clock
    )
    verifier = TokenVerifier(ISSUER, RESOURCE, ORG_ID, keys=keys)
    guard = TokenGuard(_provider, verifier, ProtectedResourceMetadata(RESOURCE, ISSUER))
    transport = httpx.ASGITransport(app=guard)
    async with httpx.AsyncClient(transport=transport, base_url="https://api.example.test") as c:
        # Before the outage, one call loads the issuer's keys.
        token = signed_token(signing_key, aud=RESOURCE)
        warm = await c.get("/api", headers={"Authorization": f"Bearer {token}"})
        assert warm.status_code == 200

        issuer.down = True
        clock.now += 20 * 60

        headers: dict[str, str] = {}
        if callable(exp):
            headers["Authorization"] = (
                f"Bearer {signed_token(signing_key, aud=RESOURCE, exp=exp())}"
            )
        response = await c.get("/api", headers=headers)

    assert response.status_code == status, consumer
    # The SDK asked the issuer nothing during the outage: the keys in hand did the work.
    assert issuer.jwks_fetches == 1
    # So the status does not show the outage: the SDK does not poll.
    assert verifier.status() == "connected"
