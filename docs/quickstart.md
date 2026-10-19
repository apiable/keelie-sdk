# Quickstart

This page takes you from nothing to a protected route in your own API. You sign up, install the
SDK, configure it, and protect one route. At the end, a call with no token gets `401`, and a call
with a Consumer's token gets your answer.

You need Python 3.9 or later, an API on FastAPI or another ASGI framework, `curl` and `jq`.

## 1. Sign up

Set the address of keelie and of its issuer once. The examples below read them.

```bash
KEELIE=https://<your keelie host>
ISSUER_HOST=https://<your issuer host>
TOKEN_URL=$ISSUER_HOST/realms/keelie/protocol/openid-connect/token
```

Sign up. `slug` is a short name for your company: lowercase letters, digits and hyphens.

```bash
curl -s -X POST $KEELIE/orgs \
  -H 'Content-Type: application/json' \
  -d '{"slug": "portal-labs", "name": "Portal Labs"}' > signup.json
jq '{id, issuer}' signup.json
```

The answer holds your org and two credentials.

| Member | What it is | Where it goes |
|---|---|---|
| `id` | Your org id. Every token of your Consumers carries it as `org_id`. | The SDK configuration |
| `issuer` | The issuer of your Consumers' tokens: your own realm. | The SDK configuration |
| `credential` | Your admin credential. It manages keelie. | Your password manager. **Never put it in your application.** |
| `sdk_credential` | The credential of the SDK. It can report usage and read your products, and nothing else. | Your application's secrets |

> **Caution:** keelie shows each client secret in this answer only. It cannot show a secret again.
> Store both secrets now, then delete `signup.json`.

## 2. Register the address of your API

keelie writes the address of your API into the `aud` claim of every Consumer token. The SDK
refuses a token that names another address. Use the exact address that a client calls, path
included, with no final slash.

```bash
ADMIN_ID=$(jq -r .credential.client_id signup.json)
ADMIN_SECRET=$(jq -r .credential.client_secret signup.json)
ORG_ID=$(jq -r .id signup.json)
ADMIN_TOKEN=$(curl -s -u "$ADMIN_ID:$ADMIN_SECRET" -d grant_type=client_credentials \
  $TOKEN_URL | jq -r .access_token)

curl -s -X PATCH $KEELIE/orgs/$ORG_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/merge-patch+json' \
  -d '{"resource": "https://api.portal-labs.example/v1"}' | jq .resource
```

keelie issues no Consumer credential before you set this address.

## 3. Install the SDK

```bash
pip install apiable
```

> **Note:** the SDK is not released yet. Until it is, install it from this repository:
> `pip install "apiable @ git+https://github.com/apiable/keelie-sdk#subdirectory=python"`.

## 4. Configure the SDK

Give your application these values from step 1 and step 2. Read them from the environment, never
from source code.

| Variable | Value |
|---|---|
| `KEELIE_URL` | The address of keelie |
| `KEELIE_TOKEN_URL` | `$TOKEN_URL` from step 1 |
| `KEELIE_ISSUER` | `issuer` from the signup answer |
| `KEELIE_ORG_ID` | `id` from the signup answer |
| `KEELIE_RESOURCE` | The address of your API from step 2 |
| `KEELIE_SDK_CLIENT_ID`, `KEELIE_SDK_CLIENT_SECRET` | `sdk_credential` from the signup answer |

The SDK takes an `httpx.AsyncClient` to talk to keelie. The SDK holds no secret of its own, so the
client carries your SDK credential. This class mints a token with it, keeps the token until it
expires, and mints again on a `401`. Copy it as it is.

```python
# keelie_auth.py
import time

import httpx


class SdkCredential(httpx.Auth):
    """Sends a token of the SDK credential with each request to keelie."""

    requires_response_body = True

    def __init__(self, token_url: str, client_id: str, client_secret: str) -> None:
        self._token_url = token_url
        self._form = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        self._token = ""
        self._expires_at = 0.0

    def auth_flow(self, request):
        if time.monotonic() >= self._expires_at:
            yield from self._mint()
        request.headers["Authorization"] = f"Bearer {self._token}"
        response = yield request
        if response.status_code == 401:
            yield from self._mint()
            request.headers["Authorization"] = f"Bearer {self._token}"
            yield request

    def _mint(self):
        response = yield httpx.Request("POST", self._token_url, data=self._form)
        response.raise_for_status()
        body = response.json()
        self._token = body["access_token"]
        # Mint again before the token expires.
        lifetime = body["expires_in"]
        self._expires_at = time.monotonic() + max(lifetime - 30, lifetime / 2)
```

## 5. Protect a route

```python
# main.py
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request

from fastapi.responses import Response

from apiable import (
    InsufficientScope,
    ProtectedResourceMetadata,
    ScopeMap,
    TokenGuard,
    TokenVerifier,
    UsageReporter,
)
from keelie_auth import SdkCredential

env = os.environ
keelie = httpx.AsyncClient(
    base_url=env["KEELIE_URL"],
    auth=SdkCredential(
        env["KEELIE_TOKEN_URL"], env["KEELIE_SDK_CLIENT_ID"], env["KEELIE_SDK_CLIENT_SECRET"]
    ),
    timeout=10,
)
verifier = TokenVerifier(env["KEELIE_ISSUER"], env["KEELIE_RESOURCE"], env["KEELIE_ORG_ID"])
metadata = ProtectedResourceMetadata(env["KEELIE_RESOURCE"], env["KEELIE_ISSUER"])
scopes = ScopeMap({("GET", "/v1/orders/{order_id}"): "orders:read"})
reporter = UsageReporter(keelie)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await reporter.start()
    yield
    await reporter.aclose()
    await keelie.aclose()


app = FastAPI(lifespan=lifespan)
app.add_middleware(TokenGuard, verifier=verifier, metadata=metadata)


@app.exception_handler(InsufficientScope)
async def insufficient_scope(request: Request, exc: InsufficientScope) -> Response:
    challenge = metadata.challenge("insufficient_scope")
    return Response(status_code=403, headers={"WWW-Authenticate": challenge})


@app.get("/v1/orders/{order_id}")
async def read_order(order_id: str, request: Request) -> dict[str, str]:
    claims = request.state.apiable_claims
    scopes.check(claims, "GET", "/v1/orders/{order_id}")  # raises InsufficientScope
    reporter.record(claims.azp, "GET /v1/orders/{order_id}", credits=1)
    return {"order_id": order_id}
```

What each line does:

- `TokenGuard` checks the token of every request under your address. It refuses a missing or bad
  token with `401`, before your route runs.
- `scopes.check` refuses a token that does not carry the scope of the route. The exception handler
  answers `InsufficientScope` with `403`.
- `reporter.record` puts one usage event in memory and returns at once. A background task sends
  the events to keelie every 5 seconds. `credits` is what the call costs the Consumer.

## 6. Check it

Start your API, then call it with no token.

```bash
curl -si https://api.portal-labs.example/v1/orders/42 | head -n 3
```

The answer is `401`, with `WWW-Authenticate: Bearer resource_metadata="..."`. An agent follows that
address to find your issuer.

## 7. Make a call with a Consumer's token

A Consumer needs a credential of their own first. Make it with `$ADMIN_TOKEN`, in this order. The
[keelie API](#the-keelie-contract) gives the body of each call.

1. `POST /products`: your API.
2. `POST /products/{productId}/plans`: a plan that grants the scope `orders:read`. Then
   `POST /plans/{planId}:publish`. A free plan needs no payment setup.
3. `POST /subjects`: the Consumer.
4. `POST /subscriptions`: the Consumer on that plan.
5. `POST /credentials` with the `subscription_id`. Store the answer's `client_id` as `CONSUMER_ID`
   and its `client_secret` as `CONSUMER_SECRET`. keelie shows the secret once.

The Consumer mints a token at your issuer and calls your API.

```bash
CONSUMER_TOKEN=$(curl -s -u "$CONSUMER_ID:$CONSUMER_SECRET" \
  -d grant_type=client_credentials \
  -d resource=https://api.portal-labs.example/v1 \
  "$(jq -r .issuer signup.json)/protocol/openid-connect/token" | jq -r .access_token)

curl -s https://api.portal-labs.example/v1/orders/42 \
  -H "Authorization: Bearer $CONSUMER_TOKEN"
```

The answer is `{"order_id": "42"}`. Within 5 seconds, the SDK reports the call to keelie.

## Next

- [Python SDK reference](python.md): every class, its arguments, its return value and its errors.
- [When keelie is down](when-keelie-is-down.md): what the SDK does in each failure.

## The keelie contract

The SDK follows two public documents. Use them if you check tokens with your own JWT library or
gateway, or if you report usage from another language.

- The keelie API, as OpenAPI:
  <https://raw.githubusercontent.com/apiable/keelie-sdk/contract/openapi/keelie.json>. It is
  published with each keelie release.
- The token rules: the claims, the order of the checks and the key set:
  <https://github.com/apiable/keelie-sdk/blob/contract/docs/token-rules.md>. They are published
  with the API.
