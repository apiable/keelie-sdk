from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from support import ORG_ID, Clock, Issuer, claims, jwk, private_key, signed_token

from apiable import TokenRejected, TokenVerifier
from apiable.keys import SigningKeys


async def test_a_valid_token_verifies_with_one_fetch_for_all_callers(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey
) -> None:
    token = signed_token(signing_key)

    results = await asyncio.gather(*(verifier.verify(token) for _ in range(5)))

    assert results[0].azp == "client-1"
    assert results[0].org_id == ORG_ID
    assert results[0].scopes == {"orders:read", "orders:write"}
    assert results[0].jti == "jti-1"
    assert issuer.jwks_fetches == 1


async def test_a_rotated_key_is_picked_up_without_a_restart(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(signed_token(signing_key))
    new_key = private_key()
    issuer.keys = [jwk("sig-2", new_key)]

    # Within the minute, an unknown kid is refused and costs the issuer nothing.
    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(signed_token(new_key, kid="sig-2"))
    assert rejected.value.reason == "kid"
    assert issuer.jwks_fetches == 1

    clock.now += 60
    claims = await verifier.verify(signed_token(new_key, kid="sig-2"))

    assert claims.azp == "client-1"
    assert issuer.jwks_fetches == 2


async def test_an_unknown_kid_fetches_once_then_is_refused(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(signed_token(signing_key))
    clock.now += 60

    for kid in ("made-up-1", "made-up-2", "made-up-3"):
        with pytest.raises(TokenRejected) as rejected:
            await verifier.verify(signed_token(signing_key, kid=kid))
        assert rejected.value.reason == "kid"

    assert issuer.jwks_fetches == 2


async def test_a_cold_cache_refuses_when_the_issuer_is_down_and_retries_next_time(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey
) -> None:
    issuer.down = True
    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(signed_token(signing_key))
    assert rejected.value.reason == "keys_unavailable"

    issuer.down = False
    claims = await verifier.verify(signed_token(signing_key))

    assert claims.azp == "client-1"


async def test_a_warm_cache_keeps_verifying_when_the_issuer_is_down(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(signed_token(signing_key))
    issuer.down = True
    clock.now += 60

    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(signed_token(signing_key, kid="sig-2"))
    assert rejected.value.reason == "kid"
    # The failed fetch also counts: the issuer is not asked again for a minute.
    issuer.down = False
    with pytest.raises(TokenRejected):
        await verifier.verify(signed_token(signing_key, kid="sig-2"))

    claims = await verifier.verify(signed_token(signing_key))
    assert claims.azp == "client-1"
    assert issuer.jwks_fetches == 1


def _hs256(_: RSAPrivateKey) -> str:
    return jwt.encode(claims(), "x" * 32, algorithm="HS256", headers={"kid": "sig-1"})


def _none(_: RSAPrivateKey) -> str:
    return jwt.encode(claims(), None, algorithm="none", headers={"kid": "sig-1"})


def _no_kid(key: RSAPrivateKey) -> str:
    return jwt.encode(claims(), key, algorithm="RS256")


def _other_signer(_: RSAPrivateKey) -> str:
    return signed_token(private_key())


def _encryption_key(key: RSAPrivateKey) -> str:
    return signed_token(key, kid="enc-rs256")


def _other_algorithm_key(key: RSAPrivateKey) -> str:
    return signed_token(key, kid="rs512")


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
        (lambda k: signed_token(k, exp=int(time.time()) - 31), "expired"),
        (lambda k: signed_token(k, exp=None), "claims"),
        (lambda k: signed_token(k, nbf=int(time.time()) + 60), "not_yet_valid"),
        (lambda k: signed_token(k, iss="https://other.example.test/realms/test"), "issuer"),
        (lambda k: signed_token(k, aud="another-api"), "audience"),
        (lambda k: signed_token(k, aud=None), "audience"),
        (lambda k: signed_token(k, azp=None), "claims"),
        (lambda k: signed_token(k, org_id="not-a-uuid"), "claims"),
        (lambda k: signed_token(k, scope=["orders:read"]), "claims"),
        (lambda k: signed_token(k, org_id=str(uuid.uuid4())), "org"),
        (lambda k: signed_token(k, typ="ID"), "typ"),
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
    claims = await verifier.verify(signed_token(signing_key, exp=int(time.time()) - 20))

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
    claims = await verifier.verify(signed_token(signing_key, kid="bare"))

    assert claims.azp == "client-1"


REALM_A = "https://issuer.example.test/realms/01890000-0000-7000-8000-00000000000a"
REALM_B = "https://issuer.example.test/realms/01890000-0000-7000-8000-00000000000b"


def _verifier_for(issuer: Issuer, clock: Clock) -> TokenVerifier:
    client = httpx.AsyncClient(transport=httpx.MockTransport(issuer.handler))
    return TokenVerifier(
        issuer.url, "provider-api", ORG_ID, keys=SigningKeys(issuer.url, client=client, clock=clock)
    )


async def test_a_token_of_another_realm_is_refused(clock: Clock) -> None:
    """Each Provider has its own realm. A verifier for realm B refuses a token of realm A, with
    A's own key and with a key both realms hold, and still verifies its own."""
    key_a, key_b = private_key(), private_key()
    realm_a, realm_b = Issuer(REALM_A), Issuer(REALM_B)
    realm_a.keys = [jwk("sig-a", key_a)]
    realm_b.keys = [jwk("sig-b", key_b), jwk("shared", key_a)]
    verifier_a, verifier_b = _verifier_for(realm_a, clock), _verifier_for(realm_b, clock)
    token_a = signed_token(key_a, kid="sig-a", iss=REALM_A)

    assert (await verifier_a.verify(token_a)).org_id == ORG_ID
    with pytest.raises(TokenRejected) as unknown_key:
        await verifier_b.verify(token_a)
    assert unknown_key.value.reason == "kid"
    with pytest.raises(TokenRejected) as wrong_issuer:
        await verifier_b.verify(signed_token(key_a, kid="shared", iss=REALM_A))
    assert wrong_issuer.value.reason == "issuer"
    assert (await verifier_b.verify(signed_token(key_b, kid="sig-b", iss=REALM_B))).azp


@pytest.mark.parametrize("says", [REALM_B, None, f"{REALM_A}x"])
async def test_a_discovery_document_of_another_issuer_fetches_no_key(
    clock: Clock, says: str | None
) -> None:
    """The discovery document must name the configured issuer (OpenID Connect Discovery 1.0,
    section 4.3). Otherwise no key is fetched, and the token is refused."""
    key = private_key()
    realm = Issuer(REALM_A, says=says)
    if says is None:
        realm.says = ""  # a document that names no issuer at all
    realm.keys = [jwk("sig-a", key)]

    with pytest.raises(TokenRejected) as rejected:
        await _verifier_for(realm, clock).verify(signed_token(key, kid="sig-a", iss=REALM_A))

    assert rejected.value.reason == "keys_unavailable"
    assert realm.jwks_fetches == 0


async def test_a_trailing_slash_on_either_side_is_the_same_issuer(clock: Clock) -> None:
    key = private_key()
    realm = Issuer(REALM_A, says=f"{REALM_A}/")
    realm.keys = [jwk("sig-a", key)]

    claims = await _verifier_for(realm, clock).verify(signed_token(key, kid="sig-a", iss=REALM_A))

    assert claims.org_id == ORG_ID


async def test_the_status_is_offline_until_the_first_token_fetches_the_keys(
    verifier: TokenVerifier, signing_key: RSAPrivateKey
) -> None:
    assert verifier.status() == "offline"

    await verifier.verify(signed_token(signing_key))

    assert verifier.status() == "connected"


async def test_the_status_is_offline_while_the_issuer_is_down_and_no_key_is_in_hand(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey
) -> None:
    issuer.down = True
    with pytest.raises(TokenRejected):
        await verifier.verify(signed_token(signing_key))

    assert verifier.status() == "offline"


async def test_the_status_is_degraded_after_a_failed_refresh_and_connected_after_a_good_one(
    verifier: TokenVerifier, issuer: Issuer, signing_key: RSAPrivateKey, clock: Clock
) -> None:
    await verifier.verify(signed_token(signing_key))
    issuer.down = True
    clock.now += 60
    with pytest.raises(TokenRejected):
        await verifier.verify(signed_token(signing_key, kid="sig-2"))

    assert verifier.status() == "degraded"

    issuer.down = False
    clock.now += 60
    with pytest.raises(TokenRejected):
        await verifier.verify(signed_token(signing_key, kid="sig-2"))

    assert verifier.status() == "connected"


async def test_a_token_whose_exp_is_a_string_is_refused(
    verifier: TokenVerifier, signing_key: RSAPrivateKey
) -> None:
    with pytest.raises(TokenRejected) as rejected:
        await verifier.verify(signed_token(signing_key, exp=str(int(time.time()) + 300)))

    assert rejected.value.reason == "claims"


async def test_the_claims_say_when_the_token_expires(
    verifier: TokenVerifier, signing_key: RSAPrivateKey
) -> None:
    exp = int(time.time()) + 300

    claims = await verifier.verify(signed_token(signing_key, exp=exp))

    assert claims.expires_at == datetime.fromtimestamp(exp, timezone.utc)
