from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from support import AUDIENCE, ISSUER, ORG_ID, Clock, Issuer, jwk, private_key

from apiable import TokenVerifier
from apiable.keys import SigningKeys


@pytest.fixture
def signing_key() -> RSAPrivateKey:
    return private_key()


@pytest.fixture
def issuer(signing_key: RSAPrivateKey) -> Issuer:
    issuer = Issuer()
    bare = jwk("bare", signing_key)
    del bare["use"], bare["alg"]
    issuer.keys = [
        # Keys that must verify nothing: one for encryption, one for another
        # algorithm, and one that cannot load. The rest of the set still loads.
        jwk("enc-1", private_key(), use="enc", alg="RSA-OAEP"),
        jwk("enc-rs256", signing_key, use="enc"),
        jwk("rs512", signing_key, alg="RS512"),
        {**jwk("broken", signing_key), "n": "!"},
        jwk("sig-1", signing_key),
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
