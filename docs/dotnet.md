# .NET SDK reference

The .NET packages of the Keelie SDK, for .NET 8 and .NET 10, with adapters for ASP.NET Core. They do
what the Python package does, by the same rules: they check each token inside your own process,
check the scope of each route or tool, and report usage in batches, after the response. Your
requests never pass through Apiable.

> **Status: in development, not released.** Nothing is on NuGet yet. Until it is released, build the
> packages from this repository (see [Install](#install)).

The [quickstart](quickstart.md) covers signup and registering your API's address. Those steps are
the same in every language. This page starts at step 3, with .NET.

| Resource | Location |
|---|---|
| Source | [`dotnet/`](../dotnet/) in this repository |
| Packages | `Keelie`, the core, and `Keelie.AspNetCore`, the ASP.NET Core adapters. Not released yet. |
| .NET | 8 or 10 |
| Dependencies | `Microsoft.Extensions.Logging.Abstractions`. The adapters add the ASP.NET Core shared framework. |
| The keelie contract | <https://raw.githubusercontent.com/apiable/keelie-sdk/contract/openapi/keelie.json>, published with each keelie release |

## Install

```bash
git clone https://github.com/apiable/keelie-sdk
cd keelie-sdk/dotnet && dotnet pack -c Release -o ../artifacts
# in your API's folder:
dotnet nuget add source /path/to/keelie-sdk/artifacts --name keelie-local
dotnet add package Keelie.AspNetCore --version 0.0.1
```

`Keelie.AspNetCore` brings `Keelie` with it.

## Get started with ASP.NET Core

Give your application the values from steps 1 and 2 of the quickstart, from the environment:
`KEELIE_URL`, `KEELIE_TOKEN_URL`, `KEELIE_ISSUER`, `KEELIE_ORG_ID`, `KEELIE_RESOURCE`,
`KEELIE_SDK_CLIENT_ID` and `KEELIE_SDK_CLIENT_SECRET`.

```csharp
using Keelie;
using Keelie.AspNetCore;

static string Env(string name) =>
    Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"{name} is not set");

using var keelie = SdkCredential.CreateClient(new SdkCredentialOptions
{
    KeelieUrl = Env("KEELIE_URL"),
    TokenUrl = Env("KEELIE_TOKEN_URL"),
    ClientId = Env("KEELIE_SDK_CLIENT_ID"),
    ClientSecret = Env("KEELIE_SDK_CLIENT_SECRET"),
});
var verifier = new TokenVerifier(Env("KEELIE_ISSUER"), Env("KEELIE_RESOURCE"), Env("KEELIE_ORG_ID"));
var metadata = new ProtectedResourceMetadata(Env("KEELIE_RESOURCE"), Env("KEELIE_ISSUER"));
var scopes = new ScopeMap(new Dictionary<string, string>
{
    ["GET /v1/orders/{orderId}"] = "orders:read",
});
await using var reporter = new UsageReporter(keelie);

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
KeelieLogging.LoggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
app.UseKeelieTokenGuard(verifier, metadata);

app.MapGet("/v1/orders/{orderId}", (string orderId, HttpContext http) =>
{
    var claims = http.GetKeelieClaims()!;
    reporter.Record(claims.Azp, "GET /v1/orders/{orderId}", credits: 1, consumerId: claims.ConsumerId);
    return Results.Ok(new { orderId });
}).RequireKeelieScope(scopes, metadata);

reporter.Start();
await app.RunAsync();
```

This is `Program.cs` of a web project (`Microsoft.NET.Sdk.Web`). The package's tests compile the same
code, in `dotnet/test/Keelie.Tests/DocExample.cs`, so it cannot drift from the package.

What each line does:

- `SdkCredential.CreateClient` makes the one `HttpClient` the SDK talks to keelie with. It mints a
  token of your SDK credential, keeps it until shortly before it expires, and mints again on a `401`.
- `UseKeelieTokenGuard` checks the token of every request under your address. It refuses a missing
  or bad token with `401`, before your endpoint runs, and puts the claims on the request.
- `RequireKeelieScope` refuses a token that does not carry the scope of the endpoint, with `403`.
- `reporter.Record` puts one usage event in memory and returns at once. A background task sends the
  events to keelie every 5 seconds. `credits` is what the call costs the Consumer. `consumerId` names
  the Consumer on a token for a person, whose `Azp` is an agent's client. On a credential's token it
  is `null`.
- When the app stops, `await using` closes the reporter, which sends what is left, once, for at most
  10 seconds.

Then check it as in steps 6 and 7 of the quickstart.

### Servers with many instances

Each process holds its own key set and its own usage buffer. That is correct: the SDK shares no
state between processes, and needs none. Make the SDK objects once in each process, never for each
request.

## Supported features

| Feature | Where |
|---|---|
| Check a token in your process | `TokenVerifier` |
| Check the scope of a route | `ScopeMap`, and `RequireKeelieScope` on an endpoint |
| Protect a REST API | `UseKeelieTokenGuard` |
| Protect a Streamable HTTP MCP server | `UseKeelieMcpGuard` |
| Tell an agent where to get a token (RFC 9728) | `ProtectedResourceMetadata`, served by each guard |
| Serve your AI Catalog | `AiCatalog`, and `UseKeelieAiCatalog` |
| Report usage, and charge an outcome once | `UsageReporter` |
| Talk to keelie with your SDK credential | `SdkCredential` |
| Logs | `KeelieLogging` |

The core, `Keelie`, has no web framework in it. Another framework can use it directly:
`TokenVerifier.VerifyAsync()`, `ScopeMap.Check()`, `ProtectedResourceMetadata` and
`AiCatalog.AnswerAsync()` take plain values.

---

## `TokenVerifier`

```csharp
new TokenVerifier(string issuer, string audience, Guid orgId, TokenVerifierOptions? options = null)
new TokenVerifier(string issuer, string audience, string orgId, TokenVerifierOptions? options = null)
```

| Argument | Value |
|---|---|
| `issuer` | `issuer` from the signup answer: your own realm. |
| `audience` | Your API's address, the `resource` you registered. Every token carries it in `aud`. Give the same value to `ProtectedResourceMetadata`. |
| `orgId` | `id` from the signup answer. As text, a value that is not a UUID throws `ArgumentException`. |
| `options.Keys` | The key set. Leave it out in production. Give one in tests (see [Test with no network](#test-with-no-network)). |
| `options.Leeway` | The clock skew a token is forgiven. 30 seconds. |

### `await verifier.VerifyAsync(string token)`

Returns the `Claims` of a token that verifies.

**Throws** `TokenRejected` for every token that does not verify. Its `Reason` is a `RejectionReason`,
and its `ReasonCode` is the same word the Python SDK logs: `malformed`, `algorithm`, `kid`,
`keys_unavailable`, `signature`, `expired`, `not_yet_valid`, `issuer`, `audience`, `claims`, `org`
or `typ`. Write the reason to your log. Never send it to the caller: a caller must not learn
"expired" from "wrong key".

The checks run in the order of the [token rules](https://github.com/apiable/keelie-sdk/blob/contract/docs/token-rules.md),
the same as in Python, with the same reason for each failure:

1. The token parses, its `alg` is `RS256`, and it names a `kid`.
2. The key with that `kid` is in the issuer's key set.
3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
4. `azp` names the credential, and `org_id` is your org id.
5. `typ` is `Bearer`.

### `verifier.Status`

What the SDK knows of the issuer, from its last fetch of the key set. It makes no network call. Show
it on your health page or in your metrics.

| Value | Meaning |
|---|---|
| `IssuerStatus.Connected` | The last fetch worked. |
| `IssuerStatus.Degraded` | The last fetch failed. The keys in hand go on verifying. The next fetch that works makes it `Connected` again. |
| `IssuerStatus.Offline` | No key in hand. Every token is refused. A new process is `Offline` until the first token fetches the key set. |

The SDK does not poll the issuer. It fetches the key set on a cold start, and for a token that
names a key it does not know, at most once a minute. To see how long a Consumer keeps working while
keelie is down, read `claims.ExpiresAt`.

### `Claims`

A record.

| Property | Type | Value |
|---|---|---|
| `Azp` | `string` | The client id of the Consumer's credential. Report usage with it. |
| `OrgId` | `Guid` | Your org id. |
| `Scopes` | `IReadOnlySet<string>` | The scopes of the token. |
| `Jti` | `string?` | The token id. Log it. Never log the token. |
| `ExpiresAt` | `DateTimeOffset` | When the token expires, from `exp`, in UTC. |
| `ConsumerId` | `Guid?` | On a token for a person, the Consumer whose credits the person uses. `Azp` is then the agent's client, which serves every Consumer. `null` on a credential's token. A value that is not a UUID refuses the token with `claims`. Report usage with it. |

---

## `ScopeMap`

```csharp
new ScopeMap(IEnumerable<KeyValuePair<string, string>> routes)
```

`routes` maps `"METHOD /template"` to one scope, such as
`["GET /v1/orders/{orderId}"] = "orders:read"`. Give the route template as you wrote it in
`MapGet` and the others, with the prefixes of its route groups, not the path of the request.

**Throws** `ArgumentException` when a key is not a method and a template, a value is not exactly
one scope, or a route is given twice.

### `scopes.Check(Claims claims, string method, string route)`

Returns when the token may call the route. **Throws** `InsufficientScope` when the token does not
carry the scope of the route, or the route is not in the map. Answer it with `403`, not `401`: the
token is good, but it does not allow this call. The check is strict: a scope matches only itself,
and a route matches only itself. There is no prefix and no wildcard.

---

## `UseKeelieTokenGuard`

```csharp
app.UseKeelieTokenGuard(verifier, metadata);
```

| Request | Answer |
|---|---|
| `GET` or `HEAD` of the metadata address | `200`, the metadata. No token is needed. |
| No Bearer token | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| A token that does not verify | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`, an empty body. The same answer for every reason. |
| A token that verifies | Your endpoint runs. It reads the claims with `HttpContext.GetKeelieClaims()`. |
| A path outside your address, or a CORS preflight (`OPTIONS`) | Your app, untouched. |

It compares the path in every form ASP.NET Core could route it by: with and without the path base,
as Kestrel decoded it, as the client sent it, with escapes read, dot segments resolved and doubled slashes folded, and without
case. ASP.NET Core routes without case, so `/V1/orders/42` reaches your `/v1/orders/{orderId}`
endpoint, and the guard checks its token. It can only guard more than your router serves, never
less.

It compares the path with the path base and without it, and it compares each form with the path of
`resource` and with each tail of that path. For a `resource` of `https://api.example.com/api/v1`, a
request under `/api/v1/` or under `/v1/` needs a token. After `UsePathBase("/api")`, ASP.NET Core
routes `/v1/orders/42` as well as `/api/v1/orders/42`, and behind a proxy that strips `/api` your app
sees only `/v1/orders/42`, so the guard checks the token in each case. The cost is that a path under
a tail, such as `/v1/health`, needs a token too, even when your app serves it outside the resource.

The verifier's `Audience` must be the `Resource` of the metadata, or `UseKeelieTokenGuard` throws
`ArgumentException` when you add it.

## `RequireKeelieScope`

```csharp
app.MapGet("/v1/orders/{orderId}", handler).RequireKeelieScope(scopes, metadata);
```

An endpoint filter that checks the endpoint it is on. The route is the request's method and the
endpoint's route template, such as `GET /v1/orders/{orderId}`, the prefixes of its route groups
included. A refused token gets `403`, `WWW-Authenticate: Bearer error="insufficient_scope",
resource_metadata="..."` and an empty body.

`UseKeelieTokenGuard` must run first. Without its claims, the endpoint throws, so the mistake shows
as a `500`. In an MVC action, call `scopes.Check(HttpContext.GetKeelieClaims()!, method, template)`
yourself.

---

## `UseKeelieMcpGuard`

```csharp
builder.Services.AddMcpServer().WithHttpTransport().WithTools<OrderTools>();
var app = builder.Build();
app.UseKeelieMcpGuard(verifier, metadata, tools, reporter);
app.MapMcp("/mcp");
```

```csharp
app.UseKeelieMcpGuard(
    TokenVerifier verifier,
    ProtectedResourceMetadata metadata,
    IReadOnlyDictionary<string, string> tools,
    UsageReporter reporter,
    int maxBodyBytes = 4 * 1024 * 1024)
```

| Argument | Value |
|---|---|
| `tools` | Each tool name and the one scope it requires, such as `["classify"] = "classify:run"`. A tool that is not here is refused. |
| `reporter` | The process's one `UsageReporter`. |
| `maxBodyBytes` | The largest body it reads. 4 MiB. |

Give the MCP endpoint itself as the `resource` of the metadata, such as
`https://api.example.com/mcp`. It works in front of `MapMcp` from the official MCP C# SDK
(`ModelContextProtocol.AspNetCore`), and in front of any other Streamable HTTP server. It reads the
body once, checks it, and hands the same bytes on to your server.

It answers as the Python `McpGuard` does:

| Request | Answer |
|---|---|
| A `tools/call` whose tool's scope the token carries | Your server. One `tool_call` event is recorded when your server starts a `2xx` response. |
| A `tools/call` whose tool's scope the token lacks, or that is not mapped | `403`, JSON-RPC `-31001`, `WWW-Authenticate: Bearer error="insufficient_scope"`. The answer does not name the scope. |
| Any other JSON-RPC method: `initialize`, `ping`, `tools/list`, `notifications/*`, `resources/*`, `prompts/*` | Your server, with no scope check. |
| A body that is not UTF-8 JSON, or is nested too deeply | `400`, `-32700` |
| A batch (an array), a body that is not an object, a key given twice, or a `tools/call` with no `id` | `400`, `-32600` |
| A `tools/call` whose `params.name` is not a string | `400`, `-32602` |
| A body over `maxBodyBytes` | `413`, `-32600` |
| `GET`, `HEAD`, `DELETE`, or a CORS preflight (`OPTIONS`) | Your server. |
| Any other method | `405`, `Allow: GET, POST, DELETE` |

Token refusals are the same as for `UseKeelieTokenGuard`. The event is recorded before the body of
the response, so a `text/event-stream` reply streams through unbuffered. It carries no credits, and
it names `claims.ConsumerId` for you.

---

## `ProtectedResourceMetadata`

```csharp
new ProtectedResourceMetadata(string resource, string authorizationServer, IEnumerable<string>? scopesSupported = null)
```

| Argument | Value |
|---|---|
| `resource` | The address of your API, exactly as a client calls it. `https`, a lowercase scheme and host, no user, query, fragment or final slash. |
| `authorizationServer` | Your `issuer`, the same value you give `TokenVerifier`. |
| `scopesSupported` | The scopes to publish. Left out, the metadata names none. |

**Throws** `ArgumentException` for an address that breaks those rules, or a scope that is not one
scope.

| Member | Value |
|---|---|
| `Path` | Where the metadata is served, such as `/.well-known/oauth-protected-resource/v1`. |
| `Url` | The full address of the metadata. |
| `Document` | The JSON document, as served. |
| `Challenge(string? error = null)` | The `WWW-Authenticate` value. Give `"invalid_token"` or `"insufficient_scope"` for a refusal you answer yourself. |
| `Protects(string path)` | `true` for the path of `resource` and every path under it. |
| `BearerToken(string? authorization)` | The Bearer token in an `Authorization` header value, or `null`. Static. |

## `AiCatalog`

```csharp
var catalog = new AiCatalog(keelie, metadata);
app.UseKeelieAiCatalog(catalog);
```

Serves your AI Catalog at `/.well-known/ard.json` (`application/json`) and
`/.well-known/ai-catalog.json` (`application/ai-catalog+json`), with no token, as in Python. Both
paths serve one body, which keelie builds from your published plans. It fetches the catalog from
keelie with your SDK credential and keeps it for 60 seconds. If keelie does not answer when the copy
is old, the answer is `503` with `Retry-After: 10` and `Cache-Control: no-store`, never an old
catalog. It asks keelie again after 10 seconds, not on each request, and one fetch serves every
request that waits on it.

Making it with `metadata` tells the guards to let a `GET` or a `HEAD` of the two catalog paths pass
with no token. The order beside the guards does not matter.

---

## `UsageReporter`

Collects usage events in memory and sends them to keelie in batches, in the background.

> **Note:** what the SDK reports is telemetry. It feeds your dashboards and the spend cap of each
> Consumer. Apiable never charges you from it.

```csharp
new UsageReporter(HttpClient keelie, UsageReporterOptions? options = null)
```

| Argument | Value |
|---|---|
| `keelie` | The client from `SdkCredential.CreateClient`, or any `HttpClient` whose `BaseAddress` is keelie and whose handler adds your SDK credential. The reporter does not dispose it. |
| `options.BatchSize` | Events in one batch, from 1 to 1000. 50. A full batch is sent at once. |
| `options.FlushInterval` | The task sends what waits at least this often. 5 seconds. Keep it at 5 seconds or less. |
| `options.MaxBufferedEvents` | 10,000. When the buffer is full, the oldest event goes, with a log line. |

**Throws** `ArgumentOutOfRangeException` when an option is out of range. Make one reporter for the
process. It is safe to call from any thread.

### `reporter.Record(clientId, capabilityKey, unit = UsageUnit.Request, quantity = 1, credits = null, outcomeId = null, consumerId = null)`

Puts one event in memory and returns at once. It does no I/O and never throws.

| Argument | Value |
|---|---|
| `clientId` | `claims.Azp`: the Consumer's credential, or the agent's client on a token for a person. |
| `capabilityKey` | The route or the tool that was called, such as `GET /v1/orders/{orderId}`. 255 characters at most. |
| `unit` | `UsageUnit.Request`, `ToolCall`, `Token` or `Outcome`. |
| `quantity` | How many units. A `decimal`, more than 0, at most six decimal places. |
| `credits` | What the call costs the Consumer's balance. Leave it out when the call is free. |
| `outcomeId` | The ID of the outcome, such as the ID of the job. Only with `UsageUnit.Outcome`. Required when the outcome has credits. 255 characters at most. |
| `consumerId` | `claims.ConsumerId`. Always pass it. It is `null` on a credential's token, and nothing is sent. |

An event that keelie would refuse is logged and left out. It cannot cost the other events of its
batch.

#### Charge an outcome once

```csharp
reporter.Record(claims.Azp, "POST /videos", credits: 0, consumerId: claims.ConsumerId); // a step
reporter.Record(claims.Azp, "POST /videos", UsageUnit.Outcome, credits: 50, outcomeId: job.Id.ToString(), consumerId: claims.ConsumerId);
```

An outcome's key is `uuid5(UsageReporter.KeelieOutcomeNamespace, outcomeId)`, with
`KeelieOutcomeNamespace = a29fa190-9b27-5a07-a1ba-3a0902a3bdcc`: the same key the Python and Node
SDKs make, so one outcome reported from any of them is still charged once. The ID must be unique
across all your Consumers. Do not give a step the outcome's ID. The [Python reference](python.md#charge-an-outcome-once)
explains why.

### `reporter.Start()`

Starts the background task. The first `Record()` starts it too.

### `await reporter.CloseAsync(TimeSpan? timeout = null)`

Stops the task and sends what is left, once. What it cannot send in `timeout` (10 seconds) is lost,
with one log line. It never throws. `await using` calls it for you.

### What happens to a batch

| keelie answers | The SDK |
|---|---|
| `2xx` | Done. |
| A network error, `401`, `408`, `409`, `429`, `5xx` | Keeps the batch, and sends it again after one interval, with the same `Idempotency-Key` and the same body. keelie keeps each event once. |
| Any other answer | Drops the batch, with a log line. A retry gets the same answer. |

## `SdkCredential`

```csharp
HttpClient SdkCredential.CreateClient(SdkCredentialOptions options)
new SdkCredential(SdkCredentialOptions options)   // a DelegatingHandler, for your own HttpClient
```

| Option | Value |
|---|---|
| `KeelieUrl` | `KEELIE_URL`. The client's base address. |
| `TokenUrl` | `KEELIE_TOKEN_URL`. |
| `ClientId`, `ClientSecret` | `sdk_credential` from the signup answer. Never your admin credential. |
| `Timeout` | How long a call to keelie may take, with the token it mints first. 10 seconds. |

It mints a token with the client credentials grant, keeps it until `max(lifetime - 30 s, lifetime / 2)`
has passed, shares one mint between every caller that waits on it, and on a `401` mints again and
sends the request once more. This is what the Python quickstart's `SdkCredential` class does; in
.NET it is part of the package.

---

## Logs

Each line is one fixed event name and its fields, the same names as in Python, such as
`apiable.token_rejected reason=expired`. They go through `Microsoft.Extensions.Logging`, under
categories that start with `Keelie`. No line holds a token or a secret.

By default, warnings go to standard error, and information and debug lines are dropped. To send
every line to your app's logging, set the factory once:

```csharp
KeelieLogging.LoggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
```

ASP.NET Core logs information by default, so the `apiable.token_rejected` lines then show. Set
`"Logging": { "LogLevel": { "Keelie": "Warning" } }` in `appsettings.json` to keep them out.

| Event | Level |
|---|---|
| `apiable.token_rejected reason=...` | Information |
| `apiable.scope_refused` | Information |
| `apiable.keys_loaded` | Information |
| `apiable.keys_unavailable` | Warning |
| `apiable.keys_not_refreshed` | Warning |
| `apiable.key_skipped` | Warning |
| `apiable.mcp_refused` | Information |
| `apiable.usage_event_invalid reason=...` | Warning |
| `apiable.usage_sent` | Debug |
| `apiable.usage_not_sent` | Warning |
| `apiable.usage_flush_failed` | Warning |
| `apiable.usage_dropped` | Warning |
| `apiable.catalog_fetch_failed` | Warning |

The meaning of each is in the [Python reference](python.md#logs).

## Test with no network

Every network call of the SDK goes through an `HttpClient` you can give it, so a test can serve its
own key set and its own keelie with an `HttpMessageHandler`:

```csharp
var keys = new SigningKeys(issuer, new SigningKeysOptions { HttpClient = new HttpClient(fakeIssuer) });
var verifier = new TokenVerifier(issuer, resource, orgId, new TokenVerifierOptions { Keys = keys });
var reporter = new UsageReporter(new HttpClient(fakeKeelie) { BaseAddress = new Uri("https://keelie.example.test") });
```

`SigningKeysOptions.TimeProvider` and `AiCatalogOptions.TimeProvider` take a `TimeProvider`, so a
test can move the clock of the key-set refresh and of the catalog cache. The package's own tests in
`dotnet/test/Keelie.Tests/` do all of this, and run ASP.NET Core on the loopback address.

## Where .NET differs from Python

| | Python | .NET |
|---|---|---|
| Framework | Any ASGI app | ASP.NET Core on .NET 8 and 10. The core takes plain values for any other framework. |
| Scope check on a REST route | `scopes.check()` in each route | `RequireKeelieScope` on each minimal API endpoint, or `scopes.Check()` |
| Route keys | `("GET", "/orders/{order_id}")` | `"GET /v1/orders/{orderId}"`: the template as written, with the prefixes of its route groups |
| The claims | `request.state.apiable_claims` | `HttpContext.GetKeelieClaims()` |
| Talking to keelie | An `httpx.AsyncClient` with the quickstart's `SdkCredential` | `SdkCredential.CreateClient()`, in the package, or any `HttpClient` with a `BaseAddress` |
| Path comparison | As the ASGI server gives it | Every form ASP.NET Core could route: with and without the path base, as decoded, as sent, escapes read, dot segments resolved, doubled slashes folded, without case |
| A path base, or a proxy that strips a prefix | Mount the guard where the app's path and `resource` agree | Guarded either way: a path under any tail of the resource path (`/v1` of `/api/v1`) needs a token, so a path such as `/v1/health` does too |
| A WebSocket under your address | Passes untouched: it is not an HTTP request in ASGI | Needs a token, as every request does. In ASP.NET Core a WebSocket starts as an HTTP request. |
| `MissingTokenChallenge` on its own | Exported | Not ported. The guards include it, as in Node. |
| A key set with an RSA key under 2048 bits | Loaded | Skipped, with `apiable.key_skipped`, as in Node |
| A key with private members (`d` and others) | Loaded as a private key | Only `n` and `e` are read, as in Node |
| Fetch of the key set | 5-second timeout on the client the SDK makes itself; redirects not followed | 5-second timeout on each document, whichever client; the SDK's own client follows no redirect. A client you give follows its own setting. |
| The status | `verifier.status()`, a string | `verifier.Status`, an `IssuerStatus` |
| The reason of a refusal | `TokenRejected.reason`, a string | `TokenRejected.Reason`, a `RejectionReason`, and `ReasonCode`, the same string as in Python |
| A `resource` with an empty query or fragment, such as `https://api.example.com/v1?` | Taken: the URL parser reads it as no query | Refused, as in Node |
| `scopes_supported` given as one string | `ValueError` | Does not compile: a string is not an `IEnumerable<string>` |
| An empty tool name in the MCP guard's `tools` | Taken | `ArgumentException` |
| A JSON-RPC body with `NaN` or `Infinity` | Read as JSON | `400`, `-32700`: not JSON by RFC 8259 |
| The background task | An asyncio task; `start()` and `aclose()` in the lifespan | A thread-pool task, started by the first `Record()` or `Start()`; `CloseAsync()` or `await using`. `Record()` is safe from any thread. |
| Amounts | `int` or `Decimal`, sent with the places as given | `decimal`. Zeros past the sixth place are dropped: `1.0000000` is sent as `1.000000`, as in Node. |
| `unit` | A string | A `UsageUnit` |
| `consumer_id` passed to `record()` | A `UUID` or its `str`, checked | A `Guid?`: a value that is not a UUID cannot be passed |
| The `ts` of an event | ISO 8601, with microseconds when they are not zero | ISO 8601, always with six decimal places |
| Logs | The `logging` module, under the logger `apiable` | `Microsoft.Extensions.Logging`, under categories that start with `Keelie`. The same event names. |
