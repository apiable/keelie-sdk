# Node SDK reference

The Node package of the Keelie SDK, for Node 22.12 or later, with adapters for Express 4 and 5. It
does what the Python package does, by the same rules: it checks each token inside your own
process, checks the scope of each route or tool, and reports usage in batches, after the response.
Your requests never pass through Apiable.

> **Status: in development, not released.** The package name `keelie` is held on npm, with no code
> in it yet. Until it is released, build it from this repository (see [Install](#install)).

The [quickstart](quickstart.md) covers signup and registering your API's address. Those steps are
the same in every language. This page starts at step 3, with Node.

## Install

```bash
git clone https://github.com/apiable/keelie-sdk
cd keelie-sdk/node && npm install && npm run build && npm pack
npm install /path/to/keelie-sdk/node/keelie-0.0.2.tgz   # in your API's folder
```

`keelie` is an ES module. From CommonJS, `require("keelie")` works on Node 22.12 and later.

## Get started with Express

Give your application the values from steps 1 and 2 of the quickstart, from the environment:
`KEELIE_URL`, `KEELIE_TOKEN_URL`, `KEELIE_ISSUER`, `KEELIE_ORG_ID`, `KEELIE_RESOURCE`,
`KEELIE_SDK_CLIENT_ID` and `KEELIE_SDK_CLIENT_SECRET`.

```ts
import express from "express";
import {
  ProtectedResourceMetadata,
  ScopeMap,
  TokenVerifier,
  UsageReporter,
  sdkCredential,
} from "keelie";
import { scopeGuard, tokenGuard } from "keelie/express";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const keelie = sdkCredential({
  keelieUrl: env("KEELIE_URL"),
  tokenUrl: env("KEELIE_TOKEN_URL"),
  clientId: env("KEELIE_SDK_CLIENT_ID"),
  clientSecret: env("KEELIE_SDK_CLIENT_SECRET"),
});
const verifier = new TokenVerifier(env("KEELIE_ISSUER"), env("KEELIE_RESOURCE"), env("KEELIE_ORG_ID"));
const metadata = new ProtectedResourceMetadata(env("KEELIE_RESOURCE"), env("KEELIE_ISSUER"));
const scopes = new ScopeMap({ "GET /v1/orders/:orderId": "orders:read" });
const reporter = new UsageReporter(keelie);

const app = express();
app.use(tokenGuard({ verifier, metadata }));

app.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), (req, res) => {
  const claims = req.keelieClaims!;
  reporter.record(claims.azp, "GET /v1/orders/:orderId", {
    credits: 1,
    consumerId: claims.consumerId,
  });
  res.json({ orderId: req.params.orderId });
});

const server = app.listen(3000);
process.on("SIGTERM", async () => {
  server.close();
  await reporter.close();
});
```

What each line does:

- `tokenGuard` checks the token of every request under your address. It refuses a missing or bad
  token with `401`, before your route runs, and puts the claims on `req.keelieClaims`.
- `scopeGuard` refuses a token that does not carry the scope of the route, with `403`.
- `reporter.record` puts one usage event in memory and returns at once. A timer sends the events to
  keelie every 5 seconds. `credits` is what the call costs the Consumer. `consumerId` names the
  Consumer on a token for a person, whose `azp` is an agent's client. On a credential's token it is
  `null`.

Then check it as in steps 6 and 7 of the quickstart.

## Supported features

| Feature | Where |
|---|---|
| Check a token in your process | `TokenVerifier` |
| Check the scope of a route | `ScopeMap`, and `scopeGuard` in Express |
| Protect a REST API | `tokenGuard` |
| Protect a Streamable HTTP MCP server | `mcpGuard` |
| Tell an agent where to get a token (RFC 9728) | `ProtectedResourceMetadata`, served by each guard |
| Serve your AI Catalog | `AiCatalog`, and `aiCatalog` in Express |
| Report usage, and charge an outcome once | `UsageReporter` |
| Talk to keelie with your SDK credential | `sdkCredential` |

The core, `keelie`, has no framework in it. The Express adapters are in `keelie/express`. Another
framework can use the core directly: `TokenVerifier.verify()`, `ScopeMap.check()`,
`ProtectedResourceMetadata` and `AiCatalog.answer()` take plain values.

---

## `TokenVerifier`

```ts
new TokenVerifier(issuer: string, audience: string, orgId: string, options?: {
  keys?: SigningKeys;
  leewaySeconds?: number; // 30
})
```

| Argument | Value |
|---|---|
| `issuer` | `issuer` from the signup answer: your own realm. |
| `audience` | Your API's address, the `resource` you registered. Every token carries it in `aud`. |
| `orgId` | `id` from the signup answer. A value that is not a UUID throws `TypeError`. |

### `await verifier.verify(token: string): Promise<Claims>`

Rejects with `TokenRejected` for every token that does not verify. Its `reason` is one of
`malformed`, `algorithm`, `kid`, `keys_unavailable`, `signature`, `expired`, `not_yet_valid`,
`issuer`, `audience`, `claims`, `org` and `typ`. Write the reason to your log. Never send it to the
caller: a caller must not learn "expired" from "wrong key".

The checks run in the order of the [token rules](https://github.com/apiable/keelie-sdk/blob/contract/docs/token-rules.md),
the same as in Python:

1. The token parses, its `alg` is `RS256`, and it names a `kid`.
2. The key with that `kid` is in the issuer's key set.
3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
4. `azp` names the credential, and `org_id` is your org id.
5. `typ` is `Bearer`.

### `verifier.status(): "connected" | "degraded" | "offline"`

What the SDK knows of the issuer, from its last fetch of the key set, as in Python. It makes no
network call.

| Value | Meaning |
|---|---|
| `connected` | The last fetch worked. |
| `degraded` | The last fetch failed. The keys in hand go on verifying. |
| `offline` | No key in hand. Every token is refused. A new process is `offline` until the first token fetches the key set. |

### `Claims`

A frozen object.

| Field | Type | Value |
|---|---|---|
| `azp` | `string` | The client id of the Consumer's credential. Report usage with it. |
| `orgId` | `string` | Your org id, lowercase with hyphens. |
| `scopes` | `ReadonlySet<string>` | The scopes of the token. |
| `jti` | `string \| null` | The token id. Log it. Never log the token. |
| `expiresAt` | `Date` | When the token expires, from `exp`. |
| `consumerId` | `string \| null` | On a token for a person, the Consumer whose credits the person uses, lowercase with hyphens. `null` on a credential's token. Report usage with it. |

---

## `ScopeMap`

```ts
new ScopeMap(routes: Record<string, string>)
```

`routes` maps `"METHOD /template"` to one scope, such as
`{ "GET /orders/:orderId": "orders:read" }`. Give the template Express matched, as you wrote it,
not the path of the request.

Throws `TypeError` when a key is not a method and a template, a value is not exactly one scope, or
a route is given twice.

### `scopes.check(claims: Claims, method: string, route: string): void`

Returns when the token may call the route. Throws `InsufficientScope` when the token does not carry
the scope of the route, or the route is not in the map. The check is strict: a scope matches only
itself, and a route matches only itself. Answer `InsufficientScope` with `403`.

---

## `tokenGuard` (Express)

```ts
app.use(tokenGuard({ verifier, metadata }));
```

| Request | Answer |
|---|---|
| `GET` or `HEAD` of the metadata address | `200`, the metadata. No token is needed. |
| No Bearer token | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| A token that does not verify | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`, an empty body. The same answer for every reason. |
| A token that verifies | Your route runs, with the claims on `req.keelieClaims`. |
| A path outside your address, or a CORS preflight (`OPTIONS`) | Your app, untouched. |

It compares the path in every form Express could route it by: as sent, with dot segments resolved,
with escapes read, with doubled slashes folded, and without case. Express routes without case
unless you set `case sensitive routing`, so `/V1/orders` reaches your `/v1/orders` route, and the
guard checks its token. It can only guard more than your router serves, never less.

The verifier's `audience` must be the `resource` of the metadata, or `tokenGuard` throws when you
make it.

## `scopeGuard` (Express)

```ts
app.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), handler);
```

Checks the route it is on. The route is the method, the path the router was mounted at, and the
route's own template. A refused token gets `403`,
`WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="..."` and an empty body.

The path the router was mounted at is read from the request. Express matches it without case unless
you set `case sensitive routing`, or `caseSensitive` on the router that holds the mount, so
`/V1/items/7` reaches the router you mounted at `/v1`. `scopeGuard` compares that part as your routers
did: without case when every router that holds a mount on the way to the route ignores case, and
exactly when any of them does not. If your map has two routes that differ only in the case of that
part, the token needs the scope of each.

`tokenGuard` must run first. Without its claims, `scopeGuard` passes an error to Express, so the
mistake shows as a `500`.

A router mounted at a path with a parameter, such as `app.use("/orgs/:orgId", router)`, gives
Express the request's own value for that part, not the template. There, call
`scopes.check(req.keelieClaims!, req.method, "/orgs/:orgId/...")` in the route.

---

## `mcpGuard` (Express)

```ts
app.use(mcpGuard({ verifier, metadata, tools, reporter, maxBodyBytes? }));
app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
```

| Argument | Value |
|---|---|
| `tools` | Each tool name and the one scope it requires, such as `{ classify: "classify:run" }`. A tool that is not here is refused. |
| `reporter` | The process's one `UsageReporter`. |
| `maxBodyBytes` | The largest body it reads. 4 MiB. |

Give the MCP endpoint itself as the `resource` of the metadata, such as
`https://api.example.com/mcp`. **Mount it before any body parser.** It reads the body once, checks
it, and hands the parsed body on as `req.body`. Pass `req.body` to your transport, as above. A body
parser mounted after it finds the body read, and leaves `req.body` alone.

It answers as the Python `McpGuard` does:

| Request | Answer |
|---|---|
| A `tools/call` whose tool's scope the token carries | Your server. One `tool_call` event is recorded when your server starts a `2xx` response. |
| A `tools/call` whose tool's scope the token lacks, or that is not mapped | `403`, JSON-RPC `-31001`, `WWW-Authenticate: Bearer error="insufficient_scope"`. The answer does not name the scope. |
| Any other JSON-RPC method | Your server, with no scope check. |
| A body that is not UTF-8 JSON, or is nested too deeply | `400`, `-32700` |
| A batch (an array), a body that is not an object, a key given twice, or a `tools/call` with no `id` | `400`, `-32600` |
| A `tools/call` whose `params.name` is not a string | `400`, `-32602` |
| A body over `maxBodyBytes` | `413`, `-32600` |
| `GET`, `HEAD` or `DELETE` | Your server. |
| Any other method | `405`, `Allow: GET, POST, DELETE` |

If a body parser has already read the body, the guard reads `req.body` as it found it, and can no
longer tell a key given twice.

---

## `ProtectedResourceMetadata`

```ts
new ProtectedResourceMetadata(resource: string, authorizationServer: string, options?: {
  scopesSupported?: Iterable<string>;
})
```

`resource` is your API's address, exactly as registered: `https`, a lowercase host, no query,
fragment or final slash. `authorizationServer` is your issuer. Each guard serves the document at
`metadata.path`, such as `/.well-known/oauth-protected-resource/v1`.

`metadata.challenge(error?)` gives the `WWW-Authenticate` value, for a refusal you answer yourself.

## `AiCatalog`

```ts
const catalog = new AiCatalog(keelie, metadata);
app.use(aiCatalog(catalog));
```

Serves your AI Catalog at `/.well-known/ard.json` and `/.well-known/ai-catalog.json`, with no
token, as in Python. It fetches the catalog from keelie with your SDK credential and keeps it for
60 seconds. If keelie does not answer when the copy is old, the answer is `503` with
`Retry-After: 10`, never an old catalog.

---

## `UsageReporter`

```ts
new UsageReporter(keelie: KeelieFetch, options?: {
  batchSize?: number;            // 50, at most 1000
  flushIntervalSeconds?: number; // 5
  maxBufferedEvents?: number;    // 10000
})
```

Make one reporter for the process. Its timer does not keep the process alive.

### `reporter.record(clientId, capabilityKey, options?): void`

| Option | Value |
|---|---|
| `unit` | `"request"` (the default), `"tool_call"`, `"token"` or `"outcome"`. |
| `quantity` | How many units. 1. |
| `credits` | What the call costs the Consumer's balance. Leave it out when the call is free. |
| `outcomeId` | The ID of the outcome of a `unit: "outcome"` event. keelie charges it once. |
| `consumerId` | `claims.consumerId`. Always pass it. |

An amount is a whole number, a decimal with at most six places, or a string that holds one, such as
`"0.25"`. Use a string for exact cents: a JavaScript `number` cannot hold every decimal exactly.
Zeros past the sixth place are dropped: `"0.0000010"` is sent as `0.000001`.

It never throws and never waits. An event keelie would refuse is left out, with the log line
`apiable.usage_event_invalid reason=...`. An option given as `null` counts as left out, as `None`
does in Python: `null` credits, `outcomeId` or `consumerId` send none, and `null` options take the
defaults. A `unit` or a `quantity` of `null` is refused, as in Python.

An outcome's key is `uuid5("a29fa190-9b27-5a07-a1ba-3a0902a3bdcc", outcomeId)`, the same key the
Python SDK makes, so one outcome reported from both is still charged once.

### `await reporter.close(timeoutSeconds = 10): Promise<void>`

Stops the timer, and sends what is in the buffer. What it cannot send in time is lost, with one log
line. It never rejects.

### What happens to a batch

As in Python. A network error, a `401`, `408`, `409`, `429` or a `5xx` keeps the batch, and it is
sent again after one interval with the same `Idempotency-Key` and the same body. Any other answer
drops it, with a log line. When the buffer is full, the oldest event goes.

## `sdkCredential`

```ts
sdkCredential({ keelieUrl, tokenUrl, clientId, clientSecret, timeoutSeconds?: 10 }): KeelieFetch
```

Sends each request to keelie with a token of your SDK credential. It mints the token with the
client credentials grant, keeps it until shortly before it expires, and mints again on a `401`.
It follows no redirect, from the token endpoint or from keelie: a `307` or `308` would send the
secret or the token on to another address. A redirect fails the request.
This is what the Python quickstart's `SdkCredential` class does; in Node it is part of the package.

---

## Logs

Each line is one fixed event name and its fields, the same names as in Python, such as
`apiable.token_rejected reason=expired`. By default `warn` goes to `console.warn`, and `info` and
`debug` are dropped. Send them to your own logger:

```ts
import { setLogger } from "keelie";
import pino from "pino";

setLogger(pino());
```

## Test with no network

`SigningKeys` takes a `fetch`, so a test can serve its own key set:

```ts
const keys = new SigningKeys(issuer, { fetch: fakeIssuerFetch });
const verifier = new TokenVerifier(issuer, resource, orgId, { keys });
```

`UsageReporter` and `AiCatalog` take any `KeelieFetch`: a function from a path and a
`RequestInit` to a `Response`. The package's own tests in `node/test/` do both.

## Where Node differs from Python

| | Python | Node |
|---|---|---|
| Framework | Any ASGI app | Express 4 and 5. The core takes plain values for any other. |
| Scope check on a REST route | `scopes.check()` in each route | `scopeGuard` on each route, or `scopes.check()` |
| Route keys | `("GET", "/orders/{order_id}")` | `"GET /orders/:orderId"` |
| The claims | `request.state.apiable_claims` | `req.keelieClaims` |
| Talking to keelie | An `httpx.AsyncClient` with the quickstart's `SdkCredential` | `sdkCredential()`, in the package |
| Path comparison | As the ASGI server gives it | Every form Express could route, without case |
| A key set with an RSA key under 2048 bits | Loaded | Skipped, with a log line. jose verifies nothing with it. |
| Callers waiting on a cold key-set fetch that fails | Each tries again in turn | All are refused with that one failure. The next caller tries again. |
