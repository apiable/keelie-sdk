from __future__ import annotations

import os
import sys
from collections.abc import Iterator

# The SDK writes no file. It holds its state in memory only, and stores nothing on the
# Provider's disk. An audit hook records each file write: at the import of the SDK, and
# during every test. A write anywhere in the SDK fails the suite.
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
_WRITE_EVENTS = frozenset(
    {"os.mkdir", "os.rename", "os.truncate", "os.symlink", "os.link", "sqlite3.connect"}
)
_writes: list[str] = []
_watching = True


def _audit(event: str, args: tuple[object, ...]) -> None:
    if not _watching:
        return
    if event == "open" and len(args) == 3:
        path, _, flags = args
        if isinstance(flags, int) and flags & _WRITE_FLAGS:
            _writes.append(f"open {path!r} flags={flags:#o}")
    elif event in _WRITE_EVENTS:
        _writes.append(f"{event} {args!r}")


# The interpreter caches the bytecode of an import on disk. That is not the SDK.
sys.dont_write_bytecode = True
sys.addaudithook(_audit)

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from support import AUDIENCE, ISSUER, ORG_ID, Clock, Issuer, jwk, private_key

from apiable import TokenVerifier
from apiable.keys import SigningKeys

_watching = False
assert not _writes, f"a file write happened at import: {_writes}"


@pytest.fixture(autouse=True)
def no_file_writes() -> Iterator[list[str]]:
    global _watching
    _writes.clear()
    _watching = True
    try:
        yield _writes
    finally:
        _watching = False
    assert not _writes, f"a file write happened during the test: {_writes}"


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
