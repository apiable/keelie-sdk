# Ruby SDK reference

The Ruby gem of the Keelie SDK, for Ruby 3.2 or later. It is Rack middleware, so it runs under
Rails, Sinatra, Hanami and any other Rack app, with a scope check for Rails controllers. It does
what the Python package does, by the same rules: it checks each token inside your own process,
checks the scope of each route or tool, and reports usage in batches, after the response. Your
requests never pass through Apiable.

> **Status: in development, not released.** The gem is not on RubyGems yet. Until it is released,
> build it from this repository (see [Install](#install)).

The [quickstart](quickstart.md) covers signup and registering your API's address. Those steps are
the same in every language. This page starts at step 3, with Ruby.

| Resource | Location |
|---|---|
| Source | [`ruby/`](../ruby/) in this repository |
| Ruby | 3.2 or later |
| Dependencies | None. It uses OpenSSL, Net::HTTP and JSON from Ruby itself. |
| Frameworks | Any Rack app. The scope check of a route is built for Rails 7.1 or later. |

## Install

```bash
git clone https://github.com/apiable/keelie-sdk
```

Then, in your API's `Gemfile`, and `bundle install`:

```ruby
gem "keelie", path: "/path/to/keelie-sdk/ruby"
```

## Get started with Rails

Give your application the values from steps 1 and 2 of the quickstart, from the environment:
`KEELIE_URL`, `KEELIE_TOKEN_URL`, `KEELIE_ISSUER`, `KEELIE_ORG_ID`, `KEELIE_RESOURCE`,
`KEELIE_SDK_CLIENT_ID` and `KEELIE_SDK_CLIENT_SECRET`.

```ruby
# config/initializers/keelie.rb
require "keelie"

KEELIE = Keelie::SdkCredential.new(
  keelie_url: ENV.fetch("KEELIE_URL"),
  token_url: ENV.fetch("KEELIE_TOKEN_URL"),
  client_id: ENV.fetch("KEELIE_SDK_CLIENT_ID"),
  client_secret: ENV.fetch("KEELIE_SDK_CLIENT_SECRET")
)
KEELIE_VERIFIER = Keelie::TokenVerifier.new(
  ENV.fetch("KEELIE_ISSUER"), ENV.fetch("KEELIE_RESOURCE"), ENV.fetch("KEELIE_ORG_ID")
)
KEELIE_METADATA = Keelie::ProtectedResourceMetadata.new(ENV.fetch("KEELIE_RESOURCE"), ENV.fetch("KEELIE_ISSUER"))
KEELIE_SCOPES = Keelie::ScopeMap.new("GET /v1/orders/:order_id" => "orders:read")
KEELIE_REPORTER = Keelie::UsageReporter.new(KEELIE)

Rails.application.config.middleware.use Keelie::Rack::TokenGuard,
                                        verifier: KEELIE_VERIFIER, metadata: KEELIE_METADATA
at_exit { KEELIE_REPORTER.close }
```

```ruby
# app/controllers/orders_controller.rb
class OrdersController < ActionController::API
  include Keelie::Rails::ScopeCheck
  keelie_scope_check KEELIE_SCOPES, KEELIE_METADATA

  def show
    claims = keelie_claims
    KEELIE_REPORTER.record(claims.azp, "GET /v1/orders/:order_id", credits: 1, consumer_id: claims.consumer_id)
    render json: { order_id: params[:order_id] }
  end
end
```

```ruby
# config/routes.rb
Rails.application.routes.draw do
  get "/v1/orders/:order_id", to: "orders#show"
end
```

What each line does:

- `Keelie::Rack::TokenGuard` checks the token of every request under your address. It refuses a
  missing or bad token with `401`, before Rails routes the request, and puts the claims in
  `request.env["keelie.claims"]`.
- `keelie_scope_check` refuses a token that does not carry the scope of the route, with `403`.
- `KEELIE_REPORTER.record` puts one usage event in memory and returns at once. A background thread
  sends the events to keelie every 5 seconds. `credits` is what the call costs the Consumer.
  `consumer_id` names the Consumer on a token for a person, whose `azp` is an agent's client. On a
  credential's token it is `nil`.

Then check it as in steps 6 and 7 of the quickstart.

The tests of the gem run this example, as it is written here, against a fake issuer and a fake
keelie.

### Servers with many workers

Each worker process holds its own key set and its own usage buffer. The SDK shares no state between
processes, and needs none. Each object is safe to share between the threads of one process.

Puma and Unicorn can load your app once and fork the workers from it (`preload_app!`). The
reporter is made before the fork, and that is correct: a forked worker starts with an empty buffer
and starts its own background thread on its first `record`. Events recorded before the fork stay
with the parent. Close the reporter in each worker as it stops. In Puma's `config/puma.rb`:

```ruby
before_worker_shutdown { KEELIE_REPORTER.close }
```

### Shut down

`KEELIE_REPORTER.close` sends the events that wait in memory, once, for at most 10 seconds. Events
it cannot send in that time are lost, with a log line. The `at_exit` line in the initializer does
this for a server that does not fork.

## Supported features

| Feature | Where |
|---|---|
| Check a token in your process | `Keelie::TokenVerifier` |
| Check the scope of a route | `Keelie::ScopeMap`, and `Keelie::Rails::ScopeCheck` in a Rails controller |
| Protect a REST API | `Keelie::Rack::TokenGuard` |
| Protect a Streamable HTTP MCP server | `Keelie::Rack::McpGuard` |
| Tell an agent where to get a token (RFC 9728) | `Keelie::ProtectedResourceMetadata`, served by each guard |
| Serve your AI Catalog | `Keelie::AiCatalog`, and `Keelie::Rack::AiCatalog` |
| Report usage, and charge an outcome once | `Keelie::UsageReporter` |
| Talk to keelie with your SDK credential | `Keelie::SdkCredential` |

The core has no framework in it. A framework other than Rails uses the Rack middleware as it is,
and calls `ScopeMap#check` in each route with the claims from `env["keelie.claims"]`.

---

## `Keelie::TokenVerifier`

```ruby
Keelie::TokenVerifier.new(issuer, audience, org_id, keys: nil, leeway_seconds: 30)
```

| Argument | Value |
|---|---|
| `issuer` | `issuer` from the signup answer: your own realm. |
| `audience` | Your API's address, the `resource` you registered. Every token carries it in `aud`. |
| `org_id` | `id` from the signup answer. A value that is not a UUID raises `ArgumentError`. |
| `keys` | The key set. Leave it out in production. Give one in tests (see [Test with no network](#test-with-no-network)). |
| `leeway_seconds` | The clock skew a token is forgiven. |

### `verifier.verify(token) -> Keelie::Claims`

Raises `Keelie::TokenRejected` for every token that does not verify. Its `reason` is one of
`:malformed`, `:algorithm`, `:kid`, `:keys_unavailable`, `:signature`, `:expired`,
`:not_yet_valid`, `:issuer`, `:audience`, `:claims`, `:org` and `:typ`. Write the reason to your
log. Never send it to the caller: a caller must not learn "expired" from "wrong key".

The checks run in the order of the [token rules](https://github.com/apiable/keelie-sdk/blob/contract/docs/token-rules.md),
the same as in Python:

1. The token parses, its `alg` is `RS256`, and it names a `kid`.
2. The key with that `kid` is in the issuer's key set.
3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
4. `azp` names the credential, and `org_id` is your org id.
5. `typ` is `Bearer`.

The reason for each token is the reason the Python SDK gives for it. The Python SDK reads a token
with PyJWT, so this class reads it by PyJWT's rules: a `jti` or a `sub` that is not a string is
`:malformed`, for example.

### `verifier.status -> :connected | :degraded | :offline`

What the SDK knows of the issuer, from its last fetch of the key set, as in Python. It makes no
network call.

| Value | Meaning |
|---|---|
| `:connected` | The last fetch worked. |
| `:degraded` | The last fetch failed. The keys in hand go on verifying. |
| `:offline` | No key in hand. Every token is refused. A new process is `:offline` until the first token fetches the key set. |

The SDK fetches the key set on the first token, and again for a `kid` it does not know, at most
once a minute. Every thread that finds the key set missing waits on one fetch. A fetch waits 5
seconds at most.

### `Keelie::Claims`

A frozen `Data`.

| Field | Type | Value |
|---|---|---|
| `azp` | `String` | The client id of the Consumer's credential. Report usage with it. |
| `org_id` | `String` | Your org id, lowercase with hyphens. |
| `scopes` | `Set` | The scopes of the token. Frozen. |
| `jti` | `String`, or `nil` | The token id. Log it. Never log the token. |
| `expires_at` | `Time` | When the token expires, from `exp`, in UTC. |
| `consumer_id` | `String`, or `nil` | On a token for a person, the Consumer whose credits the person uses, lowercase with hyphens. `nil` on a credential's token. Report usage with it. |

---

## `Keelie::ScopeMap`

```ruby
Keelie::ScopeMap.new("GET /v1/orders/:order_id" => "orders:read", "POST /v1/orders" => "orders:write")
```

Maps each route to one scope. A route is `"METHOD /template"`, or a pair
`["GET", "/v1/orders/:order_id"]`. Give the template your router matched, as you wrote it, not the
path of the request.

Raises `ArgumentError` when a key is not a method and a template, a value is not exactly one scope,
or a route is given twice.

### `scopes.check(claims, method, route)`

Returns when the token may call the route. Raises `Keelie::InsufficientScope` when the token does
not carry the scope of the route, or the route is not in the map. The check is strict: a scope
matches only itself, and a route matches only itself. Answer `InsufficientScope` with `403`, not
`401`: the token is good, but it does not allow this call.

---

## `Keelie::Rack::TokenGuard`

```ruby
use Keelie::Rack::TokenGuard, verifier: verifier, metadata: metadata            # config.ru
config.middleware.use Keelie::Rack::TokenGuard, verifier: verifier, metadata: metadata  # Rails
```

| Request | Answer |
|---|---|
| `GET` or `HEAD` of the metadata address | `200`, the metadata. No token is needed. |
| No Bearer token | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| A token that does not verify | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`, an empty body. The same answer for every reason. |
| A token that verifies | Your app, with the claims in `env["keelie.claims"]`. |
| A path outside your address, or a CORS preflight (`OPTIONS`) | Your app, untouched. |

It does not check the scope. Middleware runs before the router, so it cannot see the route
template. Check the scope in each route.

The path it compares is the path the client sent: `SCRIPT_NAME`, then `PATH_INFO`. It compares
the path in every form a Rack router could route it by: as sent, with its escapes read, with its
dot segments resolved, with its doubled slashes folded, with backslashes read as slashes, without a
format extension such as `.json`, and without case. Rails serves `/v1.json` and `//v1/orders/42`
with the routes for `/v1` and `/v1/orders/42`, and rack-protection, which Sinatra runs, resolves
`/x/..%2fv1` to `/v1`. The guard checks the token of each. It can only guard more than your router serves,
never less.

The verifier's `audience` must be the `resource` of the metadata, or the guard raises
`ArgumentError` when it is made.

## `Keelie::Rails::ScopeCheck`

```ruby
class OrdersController < ActionController::API
  include Keelie::Rails::ScopeCheck
  keelie_scope_check KEELIE_SCOPES, KEELIE_METADATA, except: :health
end
```

`keelie_scope_check(scopes, metadata, **options)` adds a `before_action`. `options` are those of
`before_action`, such as `only:` and `except:`. It checks the route Rails matched: the request's
method, and the route's path as you wrote it in `config/routes.rb`, scopes included, without
`(.:format)`. That is the template `bin/rails routes` shows, such as `GET /v1/orders/:order_id`. A
refused token gets `403`, `WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="..."`
and an empty body.

| Method | Value |
|---|---|
| `keelie_claims` | The claims of the request's token, or `nil`. |
| `keelie_route` | The route Rails matched, as the scope map names it, such as `"GET /v1/orders/:order_id"`. |

- `TokenGuard` must run first, as middleware. Without its claims, the action raises
  `Keelie::Error`, so the mistake shows as a `500`.
- Rails serves a `HEAD` request with a `GET` route. The check is then for `HEAD /v1/...`, which
  your map must name if you serve `HEAD`.
- A route of a mounted engine shows the engine's own path, without the path it is mounted at.
  There, call `KEELIE_SCOPES.check(keelie_claims, request.request_method, template)` in the action.

It needs Rails 7.1 or later, for `request.route_uri_pattern`.

---

## `Keelie::Rack::McpGuard`

```ruby
# config.ru
require "keelie"
require "mcp"

server = MCP::Server.new(name: "orders", tools: [GetOrder])
transport = MCP::Server::Transports::StreamableHTTPTransport.new(server, stateless: true)
metadata = Keelie::ProtectedResourceMetadata.new("https://api.example.com/mcp", issuer)

use Keelie::Rack::McpGuard, verifier: verifier, metadata: metadata,
                            tools: { "get_order" => "orders:read" }, reporter: reporter
map("/mcp") { run transport }
```

| Argument | Value |
|---|---|
| `tools` | Each tool name and the one scope it requires. A tool that is not here is refused. |
| `reporter` | The process's one `UsageReporter`. |
| `max_body_bytes` | The largest body it reads. 4 MiB. |

Give the MCP endpoint itself as the `resource` of the metadata. In Rails, add the guard with
`config.middleware.use` and mount the transport in `config/routes.rb`. It works with the official
MCP gem's Streamable HTTP transport, and with any other Rack app that serves MCP. Do not also give
the transport a `token_verifier` of its own.

It reads the body once, checks it, and hands the very bytes it checked to your server, in a new
`rack.input`. It answers as the Python `McpGuard` does:

| Request | Answer |
|---|---|
| A `tools/call` whose tool's scope the token carries | Your server. One `tool_call` event is recorded when your server returns a `2xx` status. |
| A `tools/call` whose tool's scope the token lacks, or that is not mapped | `403`, JSON-RPC `-31001`, `WWW-Authenticate: Bearer error="insufficient_scope"`. The answer does not name the scope. |
| Any other JSON-RPC method | Your server, with no scope check. |
| A body that is not UTF-8 JSON, or is nested more than 1000 deep | `400`, `-32700` |
| A batch (an array), a body that is not an object, a key given twice, or a `tools/call` with no `id` | `400`, `-32600` |
| A `tools/call` whose `params.name` is not a string | `400`, `-32602` |
| A body over `max_body_bytes` | `413`, `-32600` |
| `GET`, `HEAD` or `DELETE` | Your server. |
| Any other method | `405`, `Allow: GET, POST, DELETE` |

The event carries `client_id` = `azp` and the token's `consumer_id`, and no `credits`. Token
refusals are the same as for `TokenGuard`.

---

## `Keelie::ProtectedResourceMetadata`

```ruby
Keelie::ProtectedResourceMetadata.new(resource, authorization_server, scopes_supported: nil)
```

`resource` is your API's address, exactly as registered: `https`, a lowercase host, no user,
query, fragment or final slash. `authorization_server` is your issuer. `scopes_supported` is
published only if you give it. Raises `ArgumentError` for an address that breaks these rules, or a
scope list that is one string.

| Attribute or method | Value |
|---|---|
| `path` | Where the metadata is served, such as `/.well-known/oauth-protected-resource/v1`. |
| `url` | The full address of the metadata, from the configuration, never from the request's `Host`. |
| `document` | The JSON document, as served. |
| `challenge(error = nil)` | The `WWW-Authenticate` value. Give `"invalid_token"` or `"insufficient_scope"` for a refusal you answer yourself. |
| `protects?(path)` | `true` for the path of `resource` and every path under it. |

## `Keelie::AiCatalog`

```ruby
catalog = Keelie::AiCatalog.new(KEELIE, KEELIE_METADATA)
Rails.application.config.middleware.use Keelie::Rack::AiCatalog, catalog: catalog
```

Serves your AI Catalog at `/.well-known/ard.json` (`application/json`) and
`/.well-known/ai-catalog.json` (`application/ai-catalog+json`), with no token, as in Python. Both
paths serve one body. It fetches the catalog from keelie with your SDK credential and keeps it for
60 seconds. One fetch serves every request that arrives while it runs. If keelie does not answer
when the copy is old, the answer is `503` with `Retry-After: 10` and `Cache-Control: no-store`,
never an old catalog, and keelie is asked again after 10 seconds.

Made with the metadata, it tells the guards to let a `GET` or a `HEAD` of its two paths pass with
no token. Any other method on those paths is guarded like any other path. The order of the
middleware does not matter. `catalog.answer(path)` gives the Rack answer for a server that is not
Rack.

---

## `Keelie::UsageReporter`

```ruby
Keelie::UsageReporter.new(keelie, batch_size: 50, flush_interval_seconds: 5.0, max_buffered_events: 10_000)
```

| Argument | Value |
|---|---|
| `keelie` | A `Keelie::SdkCredential`. |
| `batch_size` | Events in one batch, from 1 to 1000. A full batch is sent at once. |
| `flush_interval_seconds` | The thread sends what waits at least this often. Keep it at 5 seconds or less. |
| `max_buffered_events` | When the buffer is full, the oldest event goes, with a log line. |

Raises `ArgumentError` when an argument is out of range. Make one reporter for the process.

> **Note:** what the SDK reports is telemetry. It feeds your dashboards and the spend cap of each
> Consumer. Apiable never charges you from it.

### `reporter.record(client_id, capability_key, unit: "request", quantity: 1, credits: nil, outcome_id: nil, consumer_id: nil)`

Puts one event in memory and returns at once. It does no I/O, never waits on keelie and never
raises.

| Argument | Value |
|---|---|
| `client_id` | `claims.azp`. |
| `capability_key` | The route or the tool that was called, such as `GET /v1/orders/:order_id`. 255 characters at most. |
| `unit` | `"request"`, `"tool_call"`, `"token"` or `"outcome"`, or the same as a Symbol. |
| `quantity` | How many units. An `Integer` or a `BigDecimal`, more than 0, at most six decimal places. |
| `credits` | What the call costs the Consumer's balance. Leave it out when the call is free. |
| `outcome_id` | The ID of the outcome, such as the ID of the job. Only with `unit: "outcome"`. Required when the outcome has credits. keelie charges it once. |
| `consumer_id` | `claims.consumer_id`. Always pass it. |

A `Float` is refused, as in Python: use a `BigDecimal` for cents. An event keelie would refuse is
left out, with a log line, so it cannot cost the other events of its batch.

An outcome's key is `uuid5("a29fa190-9b27-5a07-a1ba-3a0902a3bdcc", outcome_id)`
(`Keelie::KEELIE_OUTCOME_NAMESPACE`), the same key the Python SDK makes, so one outcome reported from
both is still charged once. Read [Charge an outcome once](python.md#charge-an-outcome-once) in the
Python reference: the rules are the same.

### `reporter.start`

Starts the background thread. The first `record` starts it too.

### `reporter.close(timeout = 10.0)`

Stops the thread, and sends what is left, once. A batch already on its way finishes first. What it
cannot send in `timeout` seconds is lost, with one log line. It never raises.

### What happens to a batch

As in Python. A network error, a `401`, `408`, `409`, `429` or a `5xx` keeps the batch, and it is
sent again after one interval with the same `Idempotency-Key` and the same body. Any other answer
drops it, with a log line. When the buffer is full, the oldest event goes.

## `Keelie::SdkCredential`

```ruby
Keelie::SdkCredential.new(keelie_url:, token_url:, client_id:, client_secret:, timeout_seconds: 10)
```

Sends each request to keelie with a token of your SDK credential. It mints the token with the
client credentials grant, keeps it until shortly before it expires (30 seconds before, or half its
lifetime for a short one), and mints again and retries once on a `401`. Threads that find the token
stale wait on one mint. This is what the Python quickstart's `SdkCredential` class does; in Ruby it
is part of the gem.

---

## Logs

Each line is one fixed event name and its fields, the same names as in Python, such as
`apiable.token_rejected reason=expired`. No line holds a token, a secret or a value taken from the
request. By default warnings go to standard error, and `info` and `debug` are dropped. Send them to
your own logger, such as Rails' own:

```ruby
Keelie.logger = Rails.logger
```

Any object with `debug`, `info` and `warn` fits.

| Event | Level | Meaning |
|---|---|---|
| `apiable.token_rejected reason=...` | info | A token did not verify. |
| `apiable.scope_refused` | info | A token did not carry the scope of a route. |
| `apiable.keys_loaded` | info | The SDK fetched the issuer's key set. |
| `apiable.keys_unavailable` | warn | The SDK holds no key set and could not fetch one. Every token is refused. |
| `apiable.keys_not_refreshed` | warn | A fetch failed. The keys in hand go on verifying. |
| `apiable.key_skipped` | warn | The SDK could not load one key of the set, or the key is under 2048 bits. The rest of the set loads. |
| `apiable.mcp_refused` | info | `McpGuard` refused a request. |
| `apiable.usage_event_invalid reason=...` | warn | `record` left out an event that keelie would refuse. |
| `apiable.usage_sent` | debug | keelie took a batch. |
| `apiable.usage_not_sent` | warn | A batch failed and waits for a retry. |
| `apiable.usage_flush_failed` | warn | The background thread met an error. It sends again after one interval. |
| `apiable.usage_dropped` | warn | Events were lost: refused by keelie, buffer full, or not sent at shutdown. |
| `apiable.catalog_fetch_failed` | warn | The SDK could not fetch the catalog. |

## Test with no network

Every network call of the SDK goes through an HTTP client: any object that answers
`call(method, url, body: nil, headers: {})` with a `Keelie::Response.new(status, headers, body)`.
Give your own to the objects you make:

```ruby
keys = Keelie::SigningKeys.new(issuer, http: fake_issuer)
verifier = Keelie::TokenVerifier.new(issuer, resource, org_id, keys: keys)
keelie = Keelie::SdkCredential.new(keelie_url: ..., token_url: ..., client_id: ..., client_secret: ..., http: fake)
```

Or set the client for every object made without one, such as those of your initializer:

```ruby
Keelie::HTTP.default = ->(_timeout_seconds) { fake }
```

`UsageReporter` and `AiCatalog` take any object that answers `call(method, path, body:, headers:)`
as `SdkCredential` does. The gem's own tests in `ruby/test/` do all of these. To test a refusal,
sign a token with another key, or with `exp` in the past.

## Where Ruby differs from Python

| | Python | Ruby |
|---|---|---|
| Framework | Any ASGI app | Any Rack app. The scope check of a route is built for Rails. |
| Calls | `async`: `await verifier.verify(token)` | Plain calls, safe to share between threads, such as Puma's |
| Scope check on a REST route | `scopes.check()` in each route | `keelie_scope_check` in a Rails controller, or `scopes.check` |
| Route keys | `("GET", "/orders/{order_id}")` | `"GET /orders/:order_id"`, or `["GET", "/orders/:order_id"]` |
| The claims | `request.state.apiable_claims` | `env["keelie.claims"]`, and `keelie_claims` in a controller |
| Claim types | `UUID`, `frozenset`, `datetime` | `String` (lowercase with hyphens), a frozen `Set`, a UTC `Time` |
| Refusal reasons and status | Strings, such as `"expired"` and `"connected"` | Symbols, such as `:expired` and `:connected` |
| Talking to keelie | An `httpx.AsyncClient` with the quickstart's `SdkCredential` | `Keelie::SdkCredential`, in the gem |
| Background work | An asyncio task. `start()` in the lifespan, `await aclose()` at shutdown | A thread, started by the first `record`. `close` at shutdown. A forked child starts again with an empty buffer. |
| Amounts | `int` or `Decimal`. `Decimal("1.50")` is sent as `"1.50"` | `Integer` or `BigDecimal`. `BigDecimal("1.50")` is sent as `"1.5"`, the same number. |
| `unit` | A string | A String or a Symbol |
| Path comparison | As the ASGI server gives it | Every form a Rack router could route, without case |
| A `resource` that ends in an empty query or fragment, such as `https://api.example.com/v1?` | Accepted | Refused, as in Node |
| An RSA key under 2048 bits in the key set | Loaded | Skipped, with a log line, as in Node |
| A key that publishes its private member (`d`) by mistake | PyJWT loads it as a private key, and a token it signed then fails with an error, not a refusal | Only `n` and `e` are read, as in Node |
| JSON nested deeply in an MCP body | Refused at Python's recursion limit: about 1000 on Python 3.9, far deeper on 3.12 | Refused deeper than 1000, as in Node |
| When a tool call is counted | When the server starts a `2xx` response | When the Rack app returns a `2xx` status, before the body is sent |
| Logs | The `logging` module, logger `apiable` | `Keelie.logger`. The same event names. |
