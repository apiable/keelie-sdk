# Python SDK reference

This page covers the Python SDK: how to install it, how to run it, and every public class with
its arguments, its return value and its errors. To start, read the [quickstart](quickstart.md).

| Resource | Location |
|---|---|
| Source | [`python/`](../python/) in this repository |
| Package | [`keelie-sdk` on PyPI](https://pypi.org/project/keelie-sdk/). Not released yet. You import it as `apiable`. |
| Python | 3.9 or later |
| Dependencies | `httpx`, `pyjwt[crypto]` |
| Frameworks | Any ASGI framework: FastAPI, Starlette and others |
| The keelie contract | <https://raw.githubusercontent.com/apiable/keelie-sdk/contract/openapi/keelie.json>, published with each keelie release |

## Get started

1. Install the SDK: `pip install keelie-sdk`.
2. Make one `TokenVerifier`, one `ProtectedResourceMetadata` and one `UsageReporter` for the
   process. Make them at import time or in the lifespan of your app, never for each request.
3. Mount `TokenGuard` (a REST API) or `McpGuard` (an MCP server) as middleware.
4. Start the `UsageReporter` in the lifespan of your app, and close it at shutdown.

The [quickstart](quickstart.md) shows each step with code.

> **Warning:** the guards check only the paths under your `resource`. Your app must see the same
> path as the public `resource`. A proxy or a gateway that strips the prefix, such as `/v1`, leaves
> every route unguarded. Mount the guard where the path that the app receives starts with the path
> of `resource`.

### Servers with many workers

Each worker process holds its own key set and its own usage buffer. That is correct: the SDK
shares no state between processes, and needs none. Make the SDK objects in each worker. With
`uvicorn --workers` or `gunicorn -k uvicorn.workers.UvicornWorker`, the lifespan runs in each
worker, so the code in the quickstart is already correct.

### Shut down

Call `await reporter.aclose()` in the lifespan, after `yield`. It sends the events that wait in
memory, once, for at most 10 seconds. Events it cannot send in that time are lost, with a log line.

### Serverless platforms

On AWS Lambda with Mangum, or on another serverless platform, the platform can freeze or end the
process after each invocation. The SDK has no disk buffer. Await `reporter.aclose()` before the
invocation ends, or the events in memory are lost. Make sure that the lifespan shutdown runs, or
call `aclose()` yourself at the end of the handler.

## Supported features

- [Verify a token](#tokenverifier)
- [Monitor the SDK's status](#verifierstatus)
- [Check the scope of a route](#scopemap)
- [Protect a REST API](#tokenguard)
- [Protect an MCP server](#mcpguard)
- [Tell an agent where to get a token](#protectedresourcemetadata)
- [Serve your AI Catalog](#aicatalog)
- [Report usage](#usagereporter)
- [Logs](#logs)
- [Test with no network](#test-with-no-network)
- [When keelie is down](when-keelie-is-down.md)

---

## `TokenVerifier`

Verifies the tokens of your Consumers, inside your process. It never asks keelie whether a token
is good.

```python
TokenVerifier(
    issuer: str,
    audience: str,
    org_id: UUID | str,
    *,
    keys: SigningKeys | None = None,
    leeway_seconds: int = 30,
)
```

| Argument | Value |
|---|---|
| `issuer` | The `issuer` of your org in keelie: your own realm. It must be `https`, with no user in the URL. Plain `http` is allowed only on a loopback host (`localhost`, `127.0.0.1`, `[::1]`, in any case), for local development. |
| `audience` | The address of your API, as you registered it with keelie. Give the same value to `ProtectedResourceMetadata`. |
| `org_id` | The `id` of your org in keelie. A token of another Provider carries another `org_id`. |
| `keys` | The key set. Leave it out in production. Give one in tests (see [Test with no network](#test-with-no-network)). |
| `leeway_seconds` | The clock skew a token is forgiven. |

**Raises** `ValueError` when `issuer` is not `https` and not `http` on a loopback host.

### `await verifier.verify(token: str) -> Claims`

Returns the claims of a token that verifies.

**Raises** `TokenRejected` for every token that does not verify. Its `reason` is one of
`malformed`, `algorithm`, `kid`, `keys_unavailable`, `signature`, `expired`, `not_yet_valid`,
`issuer`, `audience`, `claims`, `org` and `typ`. Write the reason to your log. Never send it to
the caller: a caller must not learn "expired" from "wrong key".

The checks run in this order. The first that fails refuses the token.

1. The token parses, its `alg` is `RS256`, and it names a `kid`.
2. The key with that `kid` is in the issuer's key set.
3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
4. `azp` names the credential, and `org_id` is your org id.
5. `typ` is `Bearer`.

### `verifier.status()`

Returns `"connected"`, `"degraded"` or `"offline"`: what the SDK knows of the issuer, from its last
fetch of the key set. It makes no network call. Show it on your health page or in your metrics.

| Value | Meaning |
|---|---|
| `connected` | The last fetch worked. |
| `degraded` | The last fetch failed. The keys in hand go on verifying. The next fetch that works makes it `connected` again. |
| `offline` | No key in hand. Every token is refused. A new process is `offline` until the first token fetches the key set. |

The SDK does not poll the issuer. It fetches the key set on a cold start, and for a token that
names a key it does not know. So while the keys in hand verify every token, an outage of the
issuer does not change the status. That is correct: during such an outage, the SDK serves every
valid token.

To see how long a Consumer keeps working while keelie is down, read `claims.expires_at`. Each
token has its own lifetime, so the time left belongs to the token, not to the process.

### The key set

- **Cold start.** With no key set in hand, all callers wait on one shared fetch. They all get its
  result, a failure too. After a failed fetch, the SDK waits 5 seconds before it asks the issuer
  again. A token in that window is refused at once, with `keys_unavailable`.
- **Deadline.** Each request to the issuer has a total deadline of 5 seconds.
- **An empty key set.** A fetch that brings no usable signing key, such as `{"keys": []}`, is a
  failed fetch. The keys in hand stay and go on verifying. The status becomes `degraded`.
- **Rotation.** A key set with a usable key replaces the old set. So a rotation retires the old
  keys.
- **https.** The `jwks_uri` in the issuer's discovery document must be `https`, or `http` on a
  loopback host. Otherwise the SDK fetches no key from it.

### `Claims`

A frozen dataclass.

| Field | Type | Value |
|---|---|---|
| `azp` | `str` | The client id of the Consumer's credential. Report usage with it. |
| `org_id` | `UUID` | Your org id. |
| `scopes` | `frozenset[str]` | The scopes of the token. |
| `jti` | `str \| None` | The token id. Log it. Never log the token. |
| `expires_at` | `datetime` | When the token expires, from `exp`, in UTC. |
| `consumer_id` | `UUID \| None` | On a token for a person, the Consumer whose credits the person uses. `azp` is then the agent's client, which serves every Consumer. `None` on a credential's token. A value that is not a UUID refuses the token with `claims`. Report usage with it. |

---

## `ScopeMap`

The scope that each route requires.

```python
ScopeMap(routes: Mapping[tuple[str, str], str])
```

`routes` maps `(method, path template)` to one scope, such as
`{("GET", "/orders/{order_id}"): "orders:read"}`. Give the template that your framework matched,
not the path of the request.

**Raises** `ValueError` when a value is not exactly one scope, or a route is given twice.

### `scopes.check(claims: Claims, method: str, route: str) -> None`

Returns when the token may call the route.

**Raises** `InsufficientScope` when the token does not carry the scope of the route, or the route
is not in the map. Answer it with `403`, not `401`: the token is good, but it does not allow this
call.

The check is strict. A scope matches only itself, and a route matches only itself. There is no
prefix and no wildcard.

```python
from fastapi import Request
from fastapi.responses import Response

from apiable import InsufficientScope


@app.exception_handler(InsufficientScope)
async def insufficient_scope(request: Request, exc: InsufficientScope) -> Response:
    return Response(
        status_code=403,
        headers={"WWW-Authenticate": metadata.challenge("insufficient_scope")},
    )
```

---

## `TokenGuard`

ASGI middleware for a REST API. It checks the token of each request under your address and puts
the claims in `request.state.apiable_claims`.

```python
app.add_middleware(TokenGuard, verifier=verifier, metadata=metadata)
```

| Request | Answer |
|---|---|
| `GET` or `HEAD` of the metadata address | `200`, the metadata. No token is needed. |
| No Bearer token | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| A token that does not verify | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`, an empty body. The same answer for every reason. |
| A token that verifies | Your route runs. |
| A path outside your address, a CORS preflight, a WebSocket | Your app, untouched. |
| Any other `OPTIONS` | Guarded like any other method. A token is needed. |

A CORS preflight is an `OPTIONS` request with two headers: `Origin` and
`Access-Control-Request-Method`. It carries none of the headers `X-HTTP-Method-Override`,
`X-HTTP-Method` or `X-Method-Override`. Only a preflight passes with no token. Your CORS
middleware must answer it. A route that accepts `OPTIONS` runs only with a token that verifies.

`TokenGuard` does not check the scope. Middleware runs before the router, so it cannot see the
route template. Call `ScopeMap.check` in each route.

The verifier's `audience` must be the `resource` of the metadata. The verifier's `issuer` must be
the `authorization_server` of the metadata. Otherwise the guard does not start: it raises
`ValueError`.

The guard checks only paths under `resource`. A proxy that strips the prefix leaves every route
unguarded. See the warning in [Get started](#get-started).

---

## `McpGuard`

ASGI middleware for a Streamable HTTP MCP server. It checks the token, checks the scope of each
tool call, and reports one usage event for each tool call your server accepts.

```python
McpGuard(
    app,
    verifier: TokenVerifier,
    metadata: ProtectedResourceMetadata,
    tools: Mapping[str, str],
    reporter: UsageReporter,
    *,
    max_body_bytes: int = 4 * 1024 * 1024,
)
```

```python
metadata = ProtectedResourceMetadata("https://api.example.com/mcp", issuer)
app.add_middleware(
    McpGuard, verifier=verifier, metadata=metadata, tools=tools, reporter=reporter
)
```

`tools` maps each tool name to one scope, such as `{"get_order": "orders:read"}`. A tool that is
not in the map is refused. Give the MCP endpoint itself as the `resource` of the metadata.

| Request | Answer |
|---|---|
| `tools/call` with the scope of the tool | Your server. One usage event, `unit="tool_call"`, when your server starts a `2xx` answer. |
| `tools/call` without the scope, or for a tool that is not in the map | `403`, JSON-RPC error `-31001`, `WWW-Authenticate: Bearer error="insufficient_scope"`. The answer does not name the scope. |
| `initialize`, `ping`, `tools/list`, `notifications/*`, `resources/*`, `prompts/*` | Your server, with no scope check. |
| A body that is not UTF-8 JSON, or is nested too deeply | `400`, `-32700` |
| A batch, a key given twice, a `tools/call` with no `id` | `400`, `-32600` |
| A `tools/call` whose `params.name` is not a string | `400`, `-32602` |
| A body larger than `max_body_bytes` | `413`, `-32600` |
| `GET`, `HEAD`, `DELETE` | Your server. |
| A CORS preflight, as for `TokenGuard` | Your server, with no token. |
| Any other method, any other `OPTIONS` included | `405`, `Allow: GET, POST, DELETE`, after the token check. |

Token refusals are the same as for `TokenGuard`.

> **Warning:** `McpGuard` counts a tool call when your server starts an HTTP `2xx` answer. It does
> not read the answer. A JSON-RPC error or an `isError` result inside an HTTP `200` is counted as
> usage. Answer a failed tool call with an HTTP error status if it must not count.

---

## `ProtectedResourceMetadata`

The RFC 9728 metadata of your API, and the `401` challenge that points to it. An agent reads it to
find the issuer of your tokens.

```python
ProtectedResourceMetadata(
    resource: str,
    authorization_server: str,
    *,
    scopes_supported: Iterable[str] | None = None,
)
```

| Argument | Value |
|---|---|
| `resource` | The address of your API, exactly as a client calls it. `https`, no query, no fragment, no final slash. |
| `authorization_server` | Your `issuer`, the same value you give `TokenVerifier`. `https`, or `http` on a loopback host for local development. |
| `scopes_supported` | The scopes to publish. Left out, the metadata names none. |

**Raises** `ValueError` for an address that breaks those rules, or a scope list that is one string.

| Attribute or method | Value |
|---|---|
| `path` | Where the metadata is served, such as `/.well-known/oauth-protected-resource/v1`. |
| `url` | The full address of the metadata. |
| `challenge(error: str \| None = None) -> str` | The `WWW-Authenticate` value. Give `"invalid_token"` or `"insufficient_scope"` for a refusal. |
| `protects(path: str) -> bool` | `True` for the path of `resource` and every path under it. |

`MissingTokenChallenge` is the part of `TokenGuard` that serves the metadata and refuses a request
with no token. It does not verify a token. Use it alone only if you verify tokens in your own code.

---

## `AiCatalog`

ASGI middleware that serves your AI Catalog on your own domain, at two paths:

- `/.well-known/ard.json`, where an ARD consumer must look (ARD v0.91, section 5.1).
- `/.well-known/ai-catalog.json`, where the ai-catalog specification looks and an MCP proposal points.

Both paths serve the same body, from one copy. keelie builds the catalog from your published plans.

```python
AiCatalog(app, client: httpx.AsyncClient, metadata: ProtectedResourceMetadata)
```

```python
app.add_middleware(AiCatalog, client=keelie, metadata=metadata)
```

`client` is the same keelie client as for `UsageReporter`. `metadata` is the one your guard uses.
With it, the guard lets a `GET` or `HEAD` of either catalog path pass with no token. Any other
method on those paths is guarded like any other path.

| Case | Answer |
|---|---|
| A copy younger than 60 seconds | `200`, `Cache-Control: max-age=60`. `Content-Type: application/json` at `ard.json`, `application/ai-catalog+json` at `ai-catalog.json` |
| keelie does not answer, or answers with an error | `503`, `Retry-After: 10`. The SDK serves no copy older than 60 seconds. It asks keelie again after 10 seconds. |

---

## `UsageReporter`

Collects usage events in memory and sends them to keelie in batches, in the background.

> **Note:** what the SDK reports is telemetry. It feeds your dashboards and the spend cap of each
> Consumer. Apiable never charges you from it.

```python
UsageReporter(
    client: httpx.AsyncClient,
    *,
    batch_size: int = 50,
    flush_interval_seconds: float = 5.0,
    max_buffered_events: int = 10_000,
)
```

| Argument | Value |
|---|---|
| `client` | Carries the address of keelie and the auth of your SDK credential. The reporter does not close it. |
| `batch_size` | Events in one batch, from 1 to 1000. A full batch is sent at once. |
| `flush_interval_seconds` | The task sends what waits at least this often. Keep it at 5 seconds or less. |
| `max_buffered_events` | When the buffer is full, the oldest event goes, with a log line. |

**Raises** `ValueError` when an argument is out of range.

Make one reporter for the process.

### `reporter.record(client_id, capability_key, *, unit="request", quantity=1, credits=None, outcome_id=None, consumer_id=None) -> None`

Puts one event in memory and returns at once. It does no I/O and never raises.

| Argument | Value |
|---|---|
| `client_id` | `claims.azp`: the Consumer's credential, or the agent's client on a token for a person. |
| `capability_key` | The route or the tool that was called, such as `GET /orders/{order_id}`. 255 characters at most. |
| `unit` | `request`, `tool_call`, `token` or `outcome`. |
| `quantity` | How many units. An `int` or a `Decimal`, more than 0, at most six decimal places. Zeros past the sixth are dropped: `Decimal("0.0000010")` is sent as `0.000001`. |
| `credits` | What the call costs the Consumer's balance. Leave it out when the call is free. |
| `outcome_id` | The ID of the outcome, such as the ID of the job. Only with `unit="outcome"`. Required when the outcome has credits. 255 characters at most. |
| `consumer_id` | `claims.consumer_id`. Always pass it. A `UUID` or its `str`. It is `None` on a credential's token, and nothing is sent. |

#### Report use under a token for a person

An agent, such as Claude, acts for a person with a token for that person. Its `azp` is the agent's
client, which serves every Consumer. The token names the Consumer in `consumer_id`. Pass it with
each event, and keelie burns that Consumer's credits:

```python
reporter.record(claims.azp, "GET /orders/{order_id}", credits=1, consumer_id=claims.consumer_id)
```

- keelie refuses the whole batch, with `consumer-unknown`, when an event of an agent's client has no
  `consumer_id`, or when the Consumer does not have exactly one live subscription. The SDK drops a
  refused batch. So always pass `claims.consumer_id`. On a credential's token it is `None`, which is
  correct there.
- A subscription canceled after the call and before the report refuses the batch too.
- `McpGuard` passes `claims.consumer_id` with each tool call for you.

An event that keelie would refuse is logged and left out. It cannot cost the other events of its
batch.

#### Charge an outcome once

With a price on an outcome, the steps before it report 0 credits, and the outcome reports the
price. The call that completes an outcome can repeat: a retry, a second status request, a second
download. Give each outcome its ID, and keelie charges it once.

```python
reporter.record(claims.azp, "POST /videos", credits=0)  # a step
reporter.record(claims.azp, "POST /videos", unit="outcome", credits=50, outcome_id=str(job.id))
```

> **Warning:** do not give a step the outcome's ID. The step then takes the outcome's key, and
> keelie charges the outcome 0.

- The SDK makes the event's key from the ID: `uuid5(KEELIE_OUTCOME_NAMESPACE, outcome_id)`, with
  `KEELIE_OUTCOME_NAMESPACE = a29fa190-9b27-5a07-a1ba-3a0902a3bdcc` (in `apiable.usage`).
- keelie keeps the key of each outcome in every month. A repeat with the same key is a duplicate.
  It burns nothing.
- **The ID must be unique across all your Consumers.** keelie compares keys across your whole
  account. Use the job's UUID, not a number that starts again for each Consumer.
- `outcome_id` is a `str`. `record()` leaves out an outcome with credits and no ID, and an ID on a
  unit other than `outcome`.

**Why a UUIDv5 and not a UUIDv7.** The key must be deterministic. The same outcome must give the
same key on every retry, in every process and in every language. A UUIDv7 is new on each call, so a
repeat would get a new key and burn the balance again. If you report from another language, make
the key the same way: a UUIDv5 of the ID, in the namespace above.

#### Report an outcome with no request

When the outcome finishes in the background, no request is running. Keep the Consumer's
`claims.azp` and `claims.consumer_id` with the job when it starts, and record the outcome from the job with that value. The
reporter uses your SDK credential, as it does for every event. The
[quickstart](quickstart.md#report-an-outcome-from-a-background-job) has an example.

### `await reporter.start() -> None`

Starts the background task. Call it in the lifespan. The first `record()` inside the event loop
also starts it, but an app whose routes all run in the thread pool needs `start()`.

### `await reporter.aclose(timeout: float = 10.0) -> None`

Stops the task and sends what is left, once. What it cannot send in `timeout` seconds is lost,
with a log line.

### What happens to a batch

| keelie answers | The SDK |
|---|---|
| `2xx` | Done. |
| A network error, `401`, `408`, `409`, `429`, `5xx` | Keeps the batch, and sends it again after one interval, with the same `Idempotency-Key` and the same body. keelie keeps each event once. |
| `401` or `409` for the fifth time on one batch | Drops the batch, with `apiable.usage_dropped events=<n> reason=refused`. |
| Any other answer | Drops the batch, with a log line. A retry gets the same answer. |

keelie refuses an event older than the start of the previous month.

---

## Logs

The SDK logs through the standard `logging` module, under the logger `apiable`. It never logs a
token or a secret.

| Event | Level | Meaning |
|---|---|---|
| `apiable.token_rejected reason=...` | INFO | A token did not verify. |
| `apiable.scope_refused` | INFO | A token did not carry the scope of a route. |
| `apiable.keys_loaded` | INFO | The SDK fetched the issuer's key set. |
| `apiable.keys_unavailable` | WARNING | The SDK holds no key set and could not fetch one. Every token is refused. For 5 seconds after the failure, the SDK does not ask the issuer again. |
| `apiable.keys_not_refreshed` | WARNING | A fetch failed, or brought no usable signing key. The keys in hand go on verifying. |
| `apiable.key_skipped` | WARNING | The SDK could not load one key of the set. The rest of the set loads. Only a key's public part is read, so a key published with its private part still loads. |
| `apiable.mcp_refused` | INFO | `McpGuard` refused a request. |
| `apiable.usage_event_invalid reason=...` | WARNING | `record()` left out an event that keelie would refuse. |
| `apiable.usage_not_sent` | WARNING | A batch failed and waits for a retry. |
| `apiable.usage_flush_failed` | WARNING | The background task met an error. It sends again after one interval. |
| `apiable.usage_dropped` | WARNING | Events were lost: refused by keelie (`reason=refused` after five `401` or `409` answers), buffer full, or not sent at shutdown. |
| `apiable.catalog_fetch_failed` | WARNING | The SDK could not fetch the catalog. |

---

## Test with no network

The SDK makes every network call through an `httpx.AsyncClient` that you can replace. Give it an
`httpx.MockTransport`, and your test suite runs with no network.

```python
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from apiable import TokenVerifier, UsageReporter
from apiable.keys import SigningKeys

ISSUER = "https://issuer.example.test/realms/test"
RESOURCE = "https://api.example.test/v1"
ORG_ID = uuid.uuid4()
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
public.update(kid="test", use="sig", alg="RS256")


def issuer(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/.well-known/openid-configuration"):
        return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/certs"})
    return httpx.Response(200, json={"keys": [public]})


keys = SigningKeys(ISSUER, client=httpx.AsyncClient(transport=httpx.MockTransport(issuer)))
verifier = TokenVerifier(ISSUER, RESOURCE, ORG_ID, keys=keys)
keelie = httpx.MockTransport(lambda request: httpx.Response(200))
reporter = UsageReporter(httpx.AsyncClient(base_url="https://keelie.example.test", transport=keelie))

# A token your test signs with `key`, with the claims of the token rules:
claims = {
    "iss": ISSUER,
    "aud": RESOURCE,
    "exp": int(time.time()) + 300,
    "typ": "Bearer",
    "azp": "consumer-1",
    "org_id": str(ORG_ID),
    "scope": "orders:read",
}
token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})
```

To test a refusal, sign a token with another key, or with `exp` in the past.
