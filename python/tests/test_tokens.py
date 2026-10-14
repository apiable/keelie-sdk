from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Callable

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from apiable import TokenRejected, TokenVerifier
from apiable.keys import SigningKeys

ISSUER = "https://issuer.example.test/realms/test"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "provider-api"
ORG_ID = uuid.UUID("01890000-0000-7000-8000-000000000001")


def _private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(kid: str, key: RSAPrivateKey, **extra: str) -> dict[str, str]:
    jwk: dict[str, str] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256", **extra})
    return jwk


class Issuer:
    """The issuer's discovery document and key set, served without a network."""

    def __init__(self) -> None:
        self.keys: list[dict[str, str]] = []
        self.jwks_fetches = 0
        self.down = False

    async def handler(self, request: httpx.Request) -> httpx.Response:
        # Yield, as a real fetch does, so that concurrent callers overlap.
        await asyncio.sleep(0.01)
        if self.down:
            return httpx.Response(503)
        if str(request.url) == f"{ISSUER}/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        if str(request.url) == JWKS_URI:
            self.jwks_fetches += 1
            return httpx.Response(200, json={"keys": self.keys})
        return httpx.Response(404)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def signing_key() -> RSAPrivateKey:
    return _private_key()


@pytest.fixture
def issuer(signing_key: RSAPrivateKey) -> Issuer:
    issuer = Issuer()
    bare = _jwk("bare", signing_key)
    del bare["use"], bare["alg"]
    issuer.keys = [
        # Keys that must verify nothing: one for encryption, one for another
        # algorithm, and one that cannot load. The rest of the set still loads.
        _jwk("enc-1", _private_key(), use="enc", alg="RSA-OAEP"),
        _jwk("enc-rs256", signing_key, use="enc"),
        _jwk("rs512", signing_key, alg="RS512"),
        {**_jwk("broken", signing_key), "n": "!"},
        _jwk("sig-1", signing_key),
        # A key with no `use` and no `alg` is a signing key.
        bare,
    ]
    return issuer


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def verifier(issuer: Issuer, clock: Clock) -> TokenVerifier:
    client = httpx.AsyncClient(transport=httpx.MockTransport(issuer.handler))
    keys = SigningKeys(ISSUER, client=client, clock=clock)
    return TokenVerifier(ISSUER, AUDIENCE, ORG_ID, keys=keys)


def _claims(**overrides: object) -> dict[str, object]:
    now = int(time.time())
    claims: dict[str, object] = {
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
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _token(key: RSAPrivateKey, kid: str = "sig-1", **overrides: object) -> str:
    return jwt.encode(_claims(**overrides), key, algorithm="RS256", headers={"kid": kid})


async def test_a_valid_token_verifies_with_one_fetch_for_all_callers(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey
) -> None:
    token = _token(signing_key)

    results = await asyncio.gather(*(verifier.verify(token) for _ in range(5)))

    assert results[0].azp == "client-1"
    assert results[0].org_id == ORG_ID
    assert results[0].scopes == {"orders:read", "orders:write"}
    assert results[0].jti == "jti-1"
    assert issuer.jwks_fetches == 1


async def test_a_rotated_key_is_picked_up_without_a_restart(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(_token(signing_key))
    new_key = _private_key()
    issuer.keys = [_jwk("sig-2", new_key)]

    # Within the minute, an unknown kid is refused and costs the issuer nothing.
    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(_token(new_key, kid="sig-2"))
    assert rejected.value.reason == "kid"
    assert issuer.jwks_fetches == 1

    clock.now += 60
    claims = await verifier.verify(_token(new_key, kid="sig-2"))

    assert claims.azp == "client-1"
    assert issuer.jwks_fetches == 2


async def test_an_unknown_kid_fetches_once_then_is_refused(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(_token(signing_key))
    clock.now += 60

    for kid in ("made-up-1", "made-up-2", "made-up-3"):
        with pytest.raises(TokenRejected) as rejected:
            await verifier.verify(_token(signing_key, kid=kid))
        assert rejected.value.reason == "kid"

    assert issuer.jwks_fetches == 2


async def test_a_cold_cache_refuses_when_the_issuer_is_down_and_retries_next_time(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey
) -> None:
    issuer.down = True
    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(_token(signing_key))
    assert rejected.value.reason == "keys_unavailable"

    issuer.down = False
    claims = await verifier.verify(_token(signing_key))

    assert claims.azp == "client-1"


async def test_a_warm_cache_keeps_verifying_when_the_issuer_is_down(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(_token(signing_key))
    issuer.down = True
    clock.now += 60

    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(_token(signing_key, kid="sig-2"))
    assert rejected.value.reason == "kid"
    # The failed fetch also counts: the issuer is not asked again for a minute.
    issuer.down = False
    with pytest.raises(TokenRejected):
        await verifier.verify(_token(signing_key, kid="sig-2"))

    claims = await verifier.verify(_token(signing_key))
    assert claims.azp == "client-1"
    assert issuer.jwks_fetches == 1


def _hs256(_: RSAPrivateKey) -> str:
    return jwt.encode(_claims(), "x" * 32, algorithm="HS256", headers={"kid": "sig-1"})


def _none(_: RSAPrivateKey) -> str:
    return jwt.encode(_claims(), None, algorithm="none", headers={"kid": "sig-1"})


def _no_kid(key: RSAPrivateKey) -> str:
    return jwt.encode(_claims(), key, algorithm="RS256")


def _other_signer(_: RSAPrivateKey) -> str:
    return _token(_private_key())


def _encryption_key(key: RSAPrivateKey) -> str:
    return _token(key, kid="enc-rs256")


def _other_algorithm_key(key: RSAPrivateKey) -> str:
    return _token(key, kid="rs512")


@pytest.mark.parametrize(
    ("make_token", "reason"),
    [
        (lambda _: "not-a-token", "malformed"),
        (_hs256, "algorithm"),
        (_none, "algorithm"),
        (_no_kid, "kid"),
        (_encryption_key, "kid"),
        (_other_algorithm_key, "kid"),
        (_other_signer, "signature"),
        (lambda k: _token(k, exp=int(time.time()) - 31), "expired"),
        (lambda k: _token(k, exp=None), "claims"),
        (lambda k: _token(k, nbf=int(time.time()) + 60), "not_yet_valid"),
        (lambda k: _token(k, iss="https://other.example.test/realms/test"), "issuer"),
        (lambda k: _token(k, aud="another-api"), "audience"),
        (lambda k: _token(k, aud=None), "audience"),
        (lambda k: _token(k, azp=None), "claims"),
        (lambda k: _token(k, org_id="not-a-uuid"), "claims"),
        (lambda k: _token(k, scope=["orders:read"]), "claims"),
        (lambda k: _token(k, org_id=str(uuid.uuid4())), "org"),
        (lambda k: _token(k, typ="ID"), "typ"),
    ],
)
async def test_each_failed_check_refuses_the_token(
    verifier: TokenVerifier,
    signing_key: RSAPrivateKey,
    make_token: Callable[[RSAPrivateKey], str],
    reason: str,
) -> None:
    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(make_token(signing_key))

    assert rejected.value.reason == reason


async def test_a_token_within_the_leeway_verifies(
    verifier: TokenVerifier, signing_key: RSAPrivateKey
) -> None:
    claims = await verifier.verify(_token(signing_key, exp=int(time.time()) - 20))

    assert claims.azp == "client-1"


async def test_a_wrong_algorithm_is_refused_before_any_fetch(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey
) -> None:
    for make_token in (_hs256, _none):
        with pytest.raises(TokenRejected):
            await verifier.verify(make_token(signing_key))

    assert issuer.jwks_fetches == 0


async def test_a_key_with_no_use_and_no_alg_verifies(
    verifier: TokenVerifier, signing_key: RSAPrivateKey
) -> None:
    claims = await verifier.verify(_token(signing_key, kid="bare"))

    assert claims.azp == "client-1"
