"""The quickstart's ``SdkCredential`` class, run as the page prints it."""

from __future__ import annotations

import re
import tempfile
import types
import urllib.parse
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_QUICKSTART = Path(__file__).resolve().parents[2] / "docs" / "quickstart.md"
TOKEN_URL = "https://keelie.example.test/realms/keelie/protocol/openid-connect/token"
AUDIENCE = "https://keelie.example.test/realms/keelie"
CLIENT_ID = "sdk-client"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# The key files are written here at import, before the suite watches for writes:
# the guard is for the SDK, and this is the Provider's own key file.
_DIR = Path(tempfile.mkdtemp())


def _key_file(name: str, key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> str:
    path = _DIR / f"{name}.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(path)


_EC = ec.generate_private_key(ec.SECP256R1())
_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_FILE = _key_file("ec", _EC)
RSA_FILE = _key_file("rsa", _RSA)
P384_FILE = _key_file("p384", ec.generate_private_key(ec.SECP384R1()))
SHORT_RSA_FILE = _key_file(
    "short", rsa.generate_private_key(public_exponent=65537, key_size=1024)
)


def _quickstart() -> types.ModuleType:
    text = _QUICKSTART.read_text()
    match = re.search(r"```python\n(# keelie_auth\.py\n.*?)```", text, re.DOTALL)
    assert match, "the quickstart has no keelie_auth.py block"
    module = types.ModuleType("keelie_auth")
    exec(compile(match.group(1), "keelie_auth.py", "exec"), module.__dict__)  # noqa: S102
    return module


SdkCredential = _quickstart().SdkCredential


class TokenEndpoint:
    def __init__(self) -> None:
        self.forms: list[dict[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_URL:
            self.forms.append(dict(urllib.parse.parse_qsl(request.content.decode())))
            token = f"token-{len(self.forms)}"
            return httpx.Response(200, json={"access_token": token, "expires_in": 300})
        # keelie refuses the first token once, so that the class mints again.
        if request.headers["Authorization"] == "Bearer token-1":
            return httpx.Response(401)
        return httpx.Response(200)


async def _call(auth: httpx.Auth, endpoint: TokenEndpoint) -> None:
    async with httpx.AsyncClient(auth=auth, transport=httpx.MockTransport(endpoint.handler)) as c:
        response = await c.get("https://keelie.example.test/usage")
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("key_file", "public", "algorithm"),
    [(EC_FILE, _EC.public_key(), "ES256"), (RSA_FILE, _RSA.public_key(), "RS256")],
    ids=["ec-p256", "rsa-2048"],
)
async def test_a_key_pair_signs_a_new_assertion_for_each_mint(
    key_file: str,
    public: ec.EllipticCurvePublicKey | rsa.RSAPublicKey,
    algorithm: str,
) -> None:
    endpoint = TokenEndpoint()
    auth = SdkCredential.from_private_key(TOKEN_URL, CLIENT_ID, key_file, AUDIENCE, kid="k7")

    await _call(auth, endpoint)

    assert len(endpoint.forms) == 2
    jtis = set()
    for form in endpoint.forms:
        assert set(form) == {"grant_type", "client_id", "client_assertion_type", "client_assertion"}
        assert form["grant_type"] == "client_credentials"
        assert form["client_id"] == CLIENT_ID
        assert form["client_assertion_type"] == JWT_BEARER
        assertion = form["client_assertion"]
        assert jwt.get_unverified_header(assertion) == {
            "alg": algorithm,
            "kid": "k7",
            "typ": "JWT",
        }
        claims = jwt.decode(assertion, public, algorithms=[algorithm], audience=AUDIENCE)
        assert claims["iss"] == claims["sub"] == CLIENT_ID
        assert 0 < claims["exp"] - claims["iat"] <= 60
        jtis.add(claims["jti"])
    assert len(jtis) == 2


@pytest.mark.parametrize("key_file", [P384_FILE, SHORT_RSA_FILE], ids=["ec-p384", "rsa-1024"])
def test_a_key_that_keelie_does_not_take_is_refused(key_file: str) -> None:
    with pytest.raises(ValueError, match="EC P-256, or RSA of 2048 bits or more"):
        SdkCredential.from_private_key(TOKEN_URL, CLIENT_ID, key_file, AUDIENCE)


async def test_a_client_secret_still_mints_as_before() -> None:
    endpoint = TokenEndpoint()

    await _call(SdkCredential(TOKEN_URL, CLIENT_ID, "the-secret"), endpoint)

    assert endpoint.forms == [
        {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": "the-secret"}
    ] * 2
