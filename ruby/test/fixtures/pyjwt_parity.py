"""Writes pyjwt_parity.json: edge-case tokens and the reason the Python SDK gives each.

The Ruby SDK reads a token by PyJWT's rules, so it must give every token here the
same reason as the Python SDK. ``pyjwt_parity_test.rb`` reads the file and checks that.

Run it from the Python package, so the Python SDK and its PyJWT are the ones read:

    cd python && uv run python ../ruby/test/fixtures/pyjwt_parity.py

Each run makes new keys, so every token changes. Only the public key goes into the
file. The private keys are never written.

The times are fixed, far in the past or the future, so the reasons do not change
with the day the tests run: no case sits near the leeway.
"""

from __future__ import annotations

import asyncio
import base64
import json
import pathlib
import platform
import uuid
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from apiable.keys import SigningKeys
from apiable.tokens import TokenRejected, TokenVerifier

# The values of ruby/test/support.rb.
ISSUER = "https://issuer.example.com/realms/portal-labs"
RESOURCE = "https://api.example.com/v1"
ORG_ID = "6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12"
OTHER_ORG = "0f2e1d3c-5b4a-4968-8776-a5b4c3d2e1f0"
CONSUMER = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
KID = "parity-key"

PAST = 946_684_800  # 2000-01-01
FUTURE = 4_102_444_800  # 2100-01-01
OUT = pathlib.Path(__file__).with_suffix(".json")

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# Signs with the right kid and the wrong key. Its public part is not published either.
IMPOSTOR = rsa.generate_private_key(public_exponent=65537, key_size=2048)

ABSENT = object()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def encode(part: Any) -> bytes:
    return part if isinstance(part, bytes) else json.dumps(part, separators=(",", ":")).encode()


def payload(**changes: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "azp": "consumer-client",
        "org_id": ORG_ID,
        "scope": "orders:read profile",
        "typ": "Bearer",
        "jti": "token-1",
        "sub": "service-account-user",
        "iat": PAST,
        "exp": FUTURE,
    }
    claims.update(changes)
    return {name: value for name, value in claims.items() if value is not ABSENT}


def header(**changes: Any) -> dict[str, Any]:
    head: dict[str, Any] = {"alg": "RS256", "kid": KID}
    head.update(changes)
    return {name: value for name, value in head.items() if value is not ABSENT}


def signed(head: Any = None, body: Any = None, key: rsa.RSAPrivateKey = KEY) -> str:
    head = header() if head is None else head
    body = payload() if body is None else body
    signing_input = f"{b64(encode(head))}.{b64(encode(body))}"
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64(signature)}"


def unsigned(head: Any, body: Any = None) -> str:
    body = payload() if body is None else body
    return f"{b64(encode(head))}.{b64(encode(body))}.{b64(b'sig')}"


def cases() -> list[tuple[str, str]]:
    good = signed()
    good_input = good[: good.rindex(".")]
    out: list[tuple[str, str]] = [
        ("a good token", good),
        # The shape of the token
        ("no dot", "not-a-token"),
        ("empty", ""),
        ("one dot", "a.b"),
        ("four parts", f"{good}.x"),
        ("a header that is not base64url", "!!!!.e30.c2ln"),
        ("a header that is an array", unsigned([1])),
        ("a header that is a string", unsigned("RS256")),
        ("a header that is null", unsigned(None)),
        ("a header that is not JSON", unsigned(b"not json")),
        ("a header that is not UTF-8", unsigned(b'{"alg":"RS256","kid":"\xff"}')),
        ("a header with a byte order mark", unsigned(b'\xef\xbb\xbf{"alg":"RS256","kid":"parity-key"}')),
        ("a header in UTF-16 with a byte order mark", signed(encode(header()).decode().encode("utf-16"))),
        ("a header in UTF-16BE", signed(encode(header()).decode().encode("utf-16-be"))),
        ("a header in UTF-32LE", signed(encode(header()).decode().encode("utf-32-le"))),
        ("a header with two byte order marks", unsigned(b"\xef\xbb\xbf\xef\xbb\xbf" + encode(header()))),
        ("a header in UTF-16 cut in half", unsigned(encode(header()).decode().encode("utf-16")[:-1])),
        ("a header with an invalid escape", signed(b'{"alg":"RS256","k\\id":"parity-key"}')),
        ("a header with an invalid escape in a value", signed(b'{"alg":"RS256","kid":"parity-key","x":"\\x"}')),
        ("a header with a short unicode escape", signed(b'{"alg":"RS256","kid":"parity-key","x":"\\u12"}')),
        ("a header with a unicode escape", signed(b'{"alg":"RS256","kid":"parity-\\u006bey"}')),
        ("a header with a tab in a string", signed(b'{"alg":"RS256","kid":"parity-key","x":"a\tb"}')),
        ("a header with a comment", unsigned(b'{"alg":"RS256",/* c */"kid":"parity-key"}')),
        ("a header with a trailing comma", unsigned(b'{"alg":"RS256","kid":"parity-key",}')),
        ("a header with NaN", signed(b'{"alg":"RS256","kid":"parity-key","x":NaN}')),
        ("a header with alg twice, the last RS256", signed(b'{"alg":"HS256","alg":"RS256","kid":"parity-key"}')),
        ("a header with alg twice, the last HS256", signed(b'{"alg":"RS256","alg":"HS256","kid":"parity-key"}')),
        ("a signature that is not base64url", f"{good_input}.!!!!"),
        ("an empty signature", f"{good_input}."),
        ("a short signature", f"{good_input}.{b64(b'short')}"),
        # The algorithm and the key
        ("alg none", unsigned(header(alg="none"))),
        ("alg HS256", unsigned(header(alg="HS256"))),
        ("alg in lower case", unsigned(header(alg="rs256"))),
        ("alg RS512", unsigned(header(alg="RS512"))),
        ("alg a number", unsigned(header(alg=256))),
        ("alg absent", unsigned(header(alg=ABSENT))),
        ("kid absent", unsigned(header(kid=ABSENT))),
        ("kid empty", unsigned(header(kid=""))),
        ("kid a number", unsigned(header(kid=7))),
        ("kid null", unsigned(header(kid=None))),
        ("kid unknown", signed(header(kid="other-key"))),
        ("the right kid, another key", signed(key=IMPOSTOR)),
        ("a header with typ JWT", signed(header(typ="JWT"))),
        ("crit with an unknown extension", unsigned(header(crit=["exp"]))),
        ("crit empty", unsigned(header(crit=[]))),
        ("crit a string", unsigned(header(crit="b64"))),
        ("crit b64, b64 absent", unsigned(header(crit=["b64"]))),
        ("crit b64, b64 true", signed(header(crit=["b64"], b64=True))),
        ("b64 false", signed(header(b64=False))),
        ("b64 false, empty payload", f"{b64(encode(header(b64=False)))}..{b64(b'sig')}"),
        # The payload
        ("a payload that is an array", signed(body=[1])),
        ("a payload that is null", signed(body=b"null")),
        ("a payload that is not JSON", signed(body=b"not json")),
        ("a payload that is not UTF-8", signed(body=b'{"exp":4102444800,"x":"\xff"}')),
        ("a payload with a byte order mark", signed(body=b"\xef\xbb\xbf" + encode(payload()))),
        ("a payload in UTF-16", signed(body=encode(payload()).decode().encode("utf-16"))),
        ("a payload with NaN", signed(body=encode(payload())[:-1] + b',"x":NaN}')),
        ("a payload with exp twice, the last good", signed(body=b'{"exp":946684800,' + encode(payload())[1:])),
        # The times
        ("exp absent", signed(body=payload(exp=ABSENT))),
        ("exp null", signed(body=payload(exp=None))),
        ("exp past", signed(body=payload(exp=PAST))),
        ("exp a string", signed(body=payload(exp="soon"))),
        ("exp a list", signed(body=payload(exp=[FUTURE]))),
        ("exp an object", signed(body=payload(exp={"at": FUTURE}))),
        ("exp true", signed(body=payload(exp=True))),
        ("exp false", signed(body=payload(exp=False))),
        ("exp a float", signed(body=payload(exp=FUTURE + 0.5))),
        ("exp a number in a string", signed(body=payload(exp=str(FUTURE)))),
        ("exp a number in a string with spaces", signed(body=payload(exp=f" {FUTURE} "))),
        ("exp a number in a string with underscores", signed(body=payload(exp="4_102_444_800"))),
        ("exp in exponent notation", signed(body=payload(exp="4.1e9"))),
        ("exp past the year 9999", signed(body=payload(exp=300_000_000_000))),
        ("exp the last second of 9999", signed(body=payload(exp=253_402_300_799))),
        ("exp negative", signed(body=payload(exp=-1))),
        ("nbf future", signed(body=payload(nbf=FUTURE))),
        ("nbf past", signed(body=payload(nbf=PAST))),
        ("nbf a string", signed(body=payload(nbf="soon"))),
        ("nbf null", signed(body=payload(nbf=None))),
        ("nbf true", signed(body=payload(nbf=True))),
        ("nbf a number in a string", signed(body=payload(nbf=str(PAST)))),
        ("iat future", signed(body=payload(iat=FUTURE))),
        ("iat a string", signed(body=payload(iat="soon"))),
        ("iat null", signed(body=payload(iat=None))),
        ("iat a float", signed(body=payload(iat=PAST + 0.5))),
        ("iat absent", signed(body=payload(iat=ABSENT))),
        ("iat future and exp past", signed(body=payload(iat=FUTURE, exp=PAST))),
        ("nbf future and exp past", signed(body=payload(nbf=FUTURE, exp=PAST))),
        # The issuer and the audience
        ("iss absent", signed(body=payload(iss=ABSENT))),
        ("iss another realm", signed(body=payload(iss="https://issuer.example.com/realms/other"))),
        ("iss with a trailing slash", signed(body=payload(iss=ISSUER + "/"))),
        ("iss a number", signed(body=payload(iss=7))),
        ("iss a list", signed(body=payload(iss=[ISSUER]))),
        ("iss null", signed(body=payload(iss=None))),
        ("aud absent", signed(body=payload(aud=ABSENT))),
        ("aud another API", signed(body=payload(aud="https://api.example.com/v2"))),
        ("aud empty", signed(body=payload(aud=""))),
        ("aud an empty list", signed(body=payload(aud=[]))),
        ("aud null", signed(body=payload(aud=None))),
        ("aud a number", signed(body=payload(aud=7))),
        ("aud an object", signed(body=payload(aud={"a": RESOURCE}))),
        ("aud a list with a number", signed(body=payload(aud=[RESOURCE, 7]))),
        ("aud a list with the API", signed(body=payload(aud=["https://other.example.com", RESOURCE]))),
        ("aud a list without the API", signed(body=payload(aud=["https://other.example.com"]))),
        ("aud with a trailing slash", signed(body=payload(aud=RESOURCE + "/"))),
        ("sub a number", signed(body=payload(sub=7))),
        ("sub null", signed(body=payload(sub=None))),
        ("sub absent", signed(body=payload(sub=ABSENT))),
        ("jti a number", signed(body=payload(jti=7))),
        ("jti null", signed(body=payload(jti=None))),
        ("jti absent", signed(body=payload(jti=ABSENT))),
        # The claims keelie writes
        ("org_id another org", signed(body=payload(org_id=OTHER_ORG))),
        ("org_id not a UUID", signed(body=payload(org_id="nope"))),
        ("org_id a number", signed(body=payload(org_id=7))),
        ("org_id absent", signed(body=payload(org_id=ABSENT))),
        ("org_id in upper case", signed(body=payload(org_id=ORG_ID.upper()))),
        ("org_id without hyphens", signed(body=payload(org_id=ORG_ID.replace("-", "")))),
        ("org_id in braces", signed(body=payload(org_id="{" + ORG_ID + "}"))),
        ("org_id as a URN", signed(body=payload(org_id="urn:uuid:" + ORG_ID))),
        ("azp absent", signed(body=payload(azp=ABSENT))),
        ("azp empty", signed(body=payload(azp=""))),
        ("azp a number", signed(body=payload(azp=7))),
        ("scope absent", signed(body=payload(scope=ABSENT))),
        ("scope a list", signed(body=payload(scope=["orders:read"]))),
        ("scope null", signed(body=payload(scope=None))),
        ("typ absent", signed(body=payload(typ=ABSENT))),
        ("typ ID", signed(body=payload(typ="ID"))),
        ("typ in lower case", signed(body=payload(typ="bearer"))),
        ("consumer_id a UUID", signed(body=payload(consumer_id=CONSUMER))),
        ("consumer_id in upper case", signed(body=payload(consumer_id=CONSUMER.upper()))),
        ("consumer_id null", signed(body=payload(consumer_id=None))),
        ("consumer_id not a UUID", signed(body=payload(consumer_id="nope"))),
        ("consumer_id a number", signed(body=payload(consumer_id=7))),
    ]
    return out


def public_jwk() -> dict[str, str]:
    jwk: dict[str, str] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    assert "d" not in jwk, "the private part must never be written"
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return jwk


async def reasons(tokens: list[tuple[str, str]], jwk: dict[str, str]) -> list[dict[str, Any]]:
    jwks_uri = f"{ISSUER}/protocol/openid-connect/certs"

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == f"{ISSUER}/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": jwks_uri})
        if str(request.url) == jwks_uri:
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = TokenVerifier(ISSUER, RESOURCE, ORG_ID, keys=SigningKeys(ISSUER, client=client))
        out = []
        for name, token in tokens:
            try:
                await verifier.verify(token)
                reason = None
            except TokenRejected as exc:
                reason = exc.reason
            out.append({"name": name, "token": token, "reason": reason})
        return out


def main() -> None:
    tokens = cases()
    names = [name for name, _ in tokens]
    assert len(names) == len(set(names)), "every case needs its own name"
    jwk = public_jwk()
    fixture = {
        "about": "Edge-case tokens and the reason the Python SDK gives each; null is a token it accepts. "
        "Written by pyjwt_parity.py. Do not edit by hand.",
        "python": platform.python_version(),
        "pyjwt": jwt.__version__,
        "issuer": ISSUER,
        "audience": RESOURCE,
        "org_id": str(uuid.UUID(ORG_ID)),
        "key": jwk,
        "cases": asyncio.run(reasons(tokens, jwk)),
    }
    text = json.dumps(fixture, indent=2) + "\n"
    assert "PRIVATE KEY" not in text and '"d"' not in text
    OUT.write_text(text)
    print(f"{len(tokens)} cases written to {OUT}")


if __name__ == "__main__":
    main()
