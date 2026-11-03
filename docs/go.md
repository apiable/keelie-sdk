# Go SDK reference

The Go module of the Keelie SDK, for Go 1.24 or later, with middleware for `net/http`. It does
what the Python package does, by the same rules: it checks each token inside your own process,
checks the scope of each route or tool, and reports usage in batches, after the response. Your
requests never pass through Apiable.

> **Status: in development, not released.** The module `github.com/apiable/keelie-sdk/go` has no
> tagged version yet. Until it has, use it from a clone of this repository (see [Install](#install)).

The [quickstart](quickstart.md) covers signup and registering your API's address. Those steps are
the same in every language. This page starts at step 3, with Go.

| Resource | Location |
|---|---|
| Source | [`go/`](../go/) in this repository |
| Module | `github.com/apiable/keelie-sdk/go`, package `keelie`, and `github.com/apiable/keelie-sdk/go/nethttp` |
| Go | 1.24 or later |
| Dependencies | None outside the standard library |
| Routers | `http.ServeMux`, and any router that takes an `http.Handler`, such as chi and gorilla/mux |

## Install

```bash
git clone https://github.com/apiable/keelie-sdk
cd your-api
go mod edit -require=github.com/apiable/keelie-sdk/go@v0.0.0 \
  -replace=github.com/apiable/keelie-sdk/go=../keelie-sdk/go
go mod tidy
```

The package name is `keelie`. Import it with that name, as in the example below.

## Get started with net/http

Give your application the values from steps 1 and 2 of the quickstart, from the environment:
`KEELIE_URL`, `KEELIE_TOKEN_URL`, `KEELIE_ISSUER`, `KEELIE_ORG_ID`, `KEELIE_RESOURCE`,
`KEELIE_SDK_CLIENT_ID` and `KEELIE_SDK_CLIENT_SECRET`.

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	keelie "github.com/apiable/keelie-sdk/go"
	"github.com/apiable/keelie-sdk/go/nethttp"
)

func env(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is not set", name)
	}
	return value
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	client, err := keelie.NewSDKCredential(keelie.SDKCredentialOptions{
		KeelieURL:    env("KEELIE_URL"),
		TokenURL:     env("KEELIE_TOKEN_URL"),
		ClientID:     env("KEELIE_SDK_CLIENT_ID"),
		ClientSecret: env("KEELIE_SDK_CLIENT_SECRET"),
	})
	check(err)
	verifier, err := keelie.NewTokenVerifier(env("KEELIE_ISSUER"), env("KEELIE_RESOURCE"), env("KEELIE_ORG_ID"), nil)
	check(err)
	metadata, err := keelie.NewProtectedResourceMetadata(env("KEELIE_RESOURCE"), env("KEELIE_ISSUER"), nil)
	check(err)
	scopes, err := keelie.NewScopeMap(map[string]string{"GET /v1/orders/{orderId}": "orders:read"})
	check(err)
	reporter, err := keelie.NewUsageReporter(client, nil)
	check(err)
	guard, err := nethttp.TokenGuard(verifier, metadata)
	check(err)
	scope := nethttp.ScopeGuard(scopes, metadata)

	mux := http.NewServeMux()
	mux.Handle("GET /v1/orders/{orderId}", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := nethttp.ClaimsFrom(r)
		reporter.Record(keelie.Event{
			ClientID:      claims.AZP,
			CapabilityKey: "GET /v1/orders/{orderId}",
			Credits:       "1",
			ConsumerID:    claims.ConsumerID,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"orderId": r.PathValue("orderId")})
	})))

	server := &http.Server{Addr: ":3000", Handler: guard(mux)}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-stop.Done()
	ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	_ = server.Shutdown(ctx)
	reporter.Close(ctx)
}
```

What each line does:

- `TokenGuard` checks the token of every request under your address. It refuses a missing or bad
  token with `401`, before your route runs, and puts the claims in the request's context.
- `ScopeGuard` refuses a token that does not carry the scope of the route, with `403`.
- `reporter.Record` puts one usage event in memory and returns at once. A goroutine sends the
  events to keelie every 5 seconds. `Credits` is what the call costs the Consumer. `ConsumerID`
  names the Consumer on a token for a person, whose `AZP` is an agent's client. On a credential's
  token it is `""`.
- `reporter.Close` sends what is left when the process stops.

Then check it as in steps 6 and 7 of the quickstart.

Make one verifier, one metadata and one reporter for the process, never one for each request. Each
is safe for concurrent use.

## Supported features

| Feature | Where |
|---|---|
| Check a token in your process | `TokenVerifier` |
| Check the scope of a route | `ScopeMap`, and `nethttp.ScopeGuard` |
| Protect a REST API | `nethttp.TokenGuard` |
| Protect a Streamable HTTP MCP server | `nethttp.MCPGuard` |
| Tell an agent where to get a token (RFC 9728) | `ProtectedResourceMetadata`, served by each guard |
| Serve your AI Catalog | `AICatalog`, and `nethttp.AICatalog` |
| Report usage, and charge an outcome once | `UsageReporter` |
| Talk to keelie with your SDK credential | `NewSDKCredential` |

The package `keelie` has no framework in it. The middleware is in `keelie/nethttp`. Another server
can use the core directly: `TokenVerifier.Verify`, `ScopeMap.Check`, `ProtectedResourceMetadata`
and `AICatalog.Answer` take plain values.

---

## `TokenVerifier`

```go
keelie.NewTokenVerifier(issuer, audience, orgID string, opts *keelie.TokenVerifierOptions) (*keelie.TokenVerifier, error)

type TokenVerifierOptions struct {
	Keys   *SigningKeys  // one made from issuer unless you give another
	Leeway time.Duration // 30 seconds when zero; a negative value forgives none
}
```

| Argument | Value |
|---|---|
| `issuer` | `issuer` from the signup answer: your own realm. |
| `audience` | Your API's address, the `resource` you registered. Every token carries it in `aud`. |
| `orgID` | `id` from the signup answer. A value that is not a UUID is an error. |

### `verifier.Verify(ctx context.Context, token string) (*keelie.Claims, error)`

The error is a `*keelie.TokenRejected` for every token that does not verify. Its `Reason` is one of
`malformed`, `algorithm`, `kid`, `keys_unavailable`, `signature`, `expired`, `not_yet_valid`,
`issuer`, `audience`, `claims`, `org` and `typ`. Write the reason to your log. Never send it to the
caller: a caller must not learn "expired" from "wrong key".

```go
claims, err := verifier.Verify(r.Context(), token)
var rejected *keelie.TokenRejected
if errors.As(err, &rejected) {
	log.Printf("token refused: %s", rejected.Reason)
}
```

The checks run in the order of the [token rules](https://github.com/apiable/keelie-sdk/blob/contract/docs/token-rules.md),
the same as in Python:

1. The token parses, its `alg` is `RS256`, and it names a `kid`.
2. The key with that `kid` is in the issuer's key set.
3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
4. `azp` names the credential, and `org_id` is your org id.
5. `typ` is `Bearer`.

`ctx` bounds the wait for the key set, which is fetched on a cold start and for a key the SDK does
not know. If `ctx` ends first, the token is refused with `keys_unavailable`. The fetch goes on for
the next caller.

### `verifier.Status() keelie.Status`

What the SDK knows of the issuer, from its last fetch of the key set, as in Python. It makes no
network call.

| Value | Meaning |
|---|---|
| `keelie.StatusConnected` | The last fetch worked. |
| `keelie.StatusDegraded` | The last fetch failed. The keys in hand go on verifying. |
| `keelie.StatusOffline` | No key in hand. Every token is refused. A new process is `offline` until the first token fetches the key set. |

### `Claims`

| Field | Type | Value |
|---|---|---|
| `AZP` | `string` | The client id of the Consumer's credential. Report usage with it. |
| `OrgID` | `string` | Your org id, lowercase with hyphens. |
| `Scopes` | `[]string` | The scopes of the token, each once. `claims.HasScope(s)` checks one. |
| `JTI` | `string` | The token id, or `""`. Log it. Never log the token. |
| `ExpiresAt` | `time.Time` | When the token expires, from `exp`, in UTC. |
| `ConsumerID` | `string` | On a token for a person, the Consumer whose credits the person uses, lowercase with hyphens. `""` on a credential's token. Report usage with it. |

---

## `ScopeMap`

```go
keelie.NewScopeMap(routes map[string]string) (*keelie.ScopeMap, error)
```

`routes` maps `"METHOD /template"` to one scope, such as
`{"GET /v1/orders/{orderId}": "orders:read"}`. With `http.ServeMux`, the key is the pattern you
registered, as you wrote it.

It is an error when a key is not a method and a template, a value is not exactly one scope, or a
route is given twice.

### `scopes.Check(claims *keelie.Claims, method, route string) error`

Returns `nil` when the token may call the route. Returns a `*keelie.InsufficientScope` when the token
does not carry the scope of the route, or the route is not in the map. The check is strict: a scope
matches only itself, and a route matches only itself. Answer it with `403`.

---

## `nethttp.TokenGuard`

```go
guard, err := nethttp.TokenGuard(verifier, metadata)
http.ListenAndServe(":3000", guard(mux))
```

| Request | Answer |
|---|---|
| `GET` or `HEAD` of the metadata address | `200`, the metadata. No token is needed. |
| No Bearer token | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| A token that does not verify | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`, an empty body. The same answer for every reason. |
| A token that verifies | Your handler runs. `nethttp.ClaimsFrom(r)` gives the claims. |
| A path outside your address, or a CORS preflight (`OPTIONS`) | Your handler, untouched, with no claims. |

It compares the path in every form a router could route it by: as sent, with its escapes read
(once and twice), with dot segments resolved and doubled slashes folded, and without case. So
`/V1/orders`, `/%76%31/orders`, `//v1/orders` and `/x/..%2fv1/orders` all need a token when your
address is `/v1`. It can only guard more than your router serves, never less. The metadata and the
AI Catalog paths pass with no token only as sent, exactly.

The verifier's audience must be the `resource` of the metadata, or `TokenGuard` returns an error.

A preflight reaches your handler with no claims. Register each route with its method, such as
`GET /v1/orders/{orderId}`, so that a preflight never reaches it. A route registered with no method
gets `500` from `ScopeGuard` on a preflight, because it has no claims to check.

## `nethttp.ScopeGuard`

```go
scope := nethttp.ScopeGuard(scopes, metadata)
mux.Handle("GET /v1/orders/{orderId}", scope(http.HandlerFunc(getOrder)))
```

Checks the route it is on. The route is the `http.ServeMux` pattern that matched, from
`r.Pattern`. A pattern with a method is the key as it is: a `HEAD` request, which `ServeMux` sends to
the `GET` pattern, needs the `GET` scope. A pattern with no method, such as `/v1/orders/{orderId}`,
takes the method of the request. A refused token gets `403`,
`WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="..."` and an empty body.

`TokenGuard` must run first. Without its claims, `ScopeGuard` answers `500`, so the mistake is seen.

Behind `http.StripPrefix`, a second `ServeMux` gives its own pattern, without the prefix. Write that
pattern in the scope map.

### Another router: `nethttp.ScopeGuardFor`

```go
nethttp.ScopeGuardFor(scopes, metadata, route nethttp.RouteFunc)

type RouteFunc func(r *http.Request) (method, template string)
```

`route` gives the template your router matched. With chi, put the guard on each route with
`With`, where chi has matched the whole pattern:

```go
chiRoute := func(r *http.Request) (string, string) {
	return r.Method, chi.RouteContext(r.Context()).RoutePattern()
}
router.With(nethttp.ScopeGuardFor(scopes, metadata, chiRoute)).Get("/v1/orders/{orderId}", getOrder)
```

The key in the map is then `"GET /v1/orders/{orderId}"`. With gorilla/mux, read
`mux.CurrentRoute(r).GetPathTemplate()` the same way. A template of `""` is in no map, and is refused.

---

## `nethttp.MCPGuard`

```go
guard, err := nethttp.MCPGuard(nethttp.MCPGuardOptions{
	Verifier: verifier,
	Metadata: metadata,
	Tools:    map[string]string{"classify": "classify:run"},
	Reporter: reporter,
	// MaxBodyBytes: 4 << 20, the default
})
mux.Handle("/mcp", guard(mcp.NewStreamableHTTPHandler(getServer, nil)))
```

| Option | Value |
|---|---|
| `Tools` | Each tool name and the one scope it requires. A tool that is not here is refused. |
| `Reporter` | The process's one `UsageReporter`. |
| `MaxBodyBytes` | The largest body it reads. 4 MiB. |

Give the MCP endpoint itself as the `resource` of the metadata, such as
`https://api.example.com/mcp`. It wraps any MCP server's handler; the tests run the Streamable HTTP
handler of the official Go MCP SDK, `github.com/modelcontextprotocol/go-sdk`, with its own client.
It reads the body once, checks it, and hands the same bytes on to your server. The claims are in
the request's context for your tools.

It answers as the Python `McpGuard` does:

| Request | Answer |
|---|---|
| A `tools/call` whose tool's scope the token carries | Your server. One `tool_call` event is recorded when your server starts a `2xx` response. |
| A `tools/call` whose tool's scope the token lacks, or that is not mapped | `403`, JSON-RPC `-31001`, `WWW-Authenticate: Bearer error="insufficient_scope"`. The answer does not name the scope. |
| Any other JSON-RPC method | Your server, with no scope check. |
| A body that is not UTF-8 JSON, or is nested too deeply | `400`, `-32700` |
| A batch (an array), a body that is not an object, a key given twice, or a `tools/call` with no `id` | `400`, `-32600` |
| A `tools/call` whose `params.name` is not a string | `400`, `-32602` |
| A body over `MaxBodyBytes` | `413`, `-32600` |
| `GET`, `HEAD` or `DELETE` | Your server. |
| Any other method | `405`, `Allow: GET, POST, DELETE` |

The event is recorded when your server writes its status, or its first byte, so an event stream
goes through unbuffered. The guard's response writer passes `Flush` through, and
`http.NewResponseController` reaches the writer underneath.

---

## `ProtectedResourceMetadata`

```go
keelie.NewProtectedResourceMetadata(resource, authorizationServer string, opts *keelie.ProtectedResourceMetadataOptions) (*keelie.ProtectedResourceMetadata, error)

type ProtectedResourceMetadataOptions struct {
	ScopesSupported []string // published only if not nil
}
```

`resource` is your API's address, exactly as registered: `https`, a lowercase host, no query,
fragment or final slash. `authorizationServer` is your issuer. Each guard serves the document at
`metadata.Path()`, such as `/.well-known/oauth-protected-resource/v1`.

`metadata.Challenge(code)` gives the `WWW-Authenticate` value, for a refusal you answer yourself:
`""` for a request with no token, `"invalid_token"` or `"insufficient_scope"`. It panics on a code
that is not lowercase letters and underscores.

## `AICatalog`

```go
catalog := keelie.NewAICatalog(client, metadata, nil)
handler := nethttp.AICatalog(catalog)(guard(mux))
```

Serves your AI Catalog at `/.well-known/ard.json` and `/.well-known/ai-catalog.json`, with no
token, as in Python. It fetches the catalog from keelie with your SDK credential and keeps it for
60 seconds. If keelie does not answer when the copy is old, the answer is `503` with
`Retry-After: 10`, never an old catalog. Many requests at once share one fetch.

Making the catalog with the metadata tells the guards to let a `GET` or a `HEAD` of its two paths
pass. The order of the middleware does not matter.

---

## `UsageReporter`

```go
keelie.NewUsageReporter(client keelie.KeelieClient, opts *keelie.UsageReporterOptions) (*keelie.UsageReporter, error)

type UsageReporterOptions struct {
	BatchSize         int           // 50, at most 1000
	FlushInterval     time.Duration // 5 seconds
	MaxBufferedEvents int           // 10000
}
```

Make one reporter for the process. The first `Record` starts its goroutine; `Start()` starts it
sooner.

### `reporter.Record(e keelie.Event)`

| Field | Value |
|---|---|
| `ClientID` | `claims.AZP`. Required. |
| `CapabilityKey` | The route or the tool that was called, 255 characters at most. Required. |
| `Unit` | `keelie.UnitRequest` (the default), `UnitToolCall`, `UnitToken` or `UnitOutcome`. |
| `Quantity` | How many units, as an amount. `"1"` when empty. |
| `Credits` | What the call costs the Consumer's balance, as an amount. Leave it empty when the call is free. |
| `OutcomeID` | The ID of the outcome of a `UnitOutcome` event. keelie charges it once. |
| `ConsumerID` | `claims.ConsumerID`. Always pass it. |

An amount is a decimal string, such as `"1"` or `"0.25"`: no sign, no exponent, at most six
places, at most `1000000000`. A string keeps exact cents that a float cannot.

It never fails and never waits on the network. An event keelie would refuse is left out, with a log
line.

An outcome's key is `uuid5("a29fa190-9b27-5a07-a1ba-3a0902a3bdcc", OutcomeID)`, the same key the
Python SDK makes, so one outcome reported from both is still charged once. The namespace is
`keelie.KeelieOutcomeNamespace`.

### `reporter.Close(ctx context.Context)`

Stops the goroutine, and sends what is in the buffer. It gives up when `ctx` ends, or after
10 seconds when `ctx` has no deadline. What it cannot send in time is lost, with one log line.
`Record` does nothing after `Close`.

### What happens to a batch

As in Python. A network error, a `401`, `408`, `409`, `429` or a `5xx` keeps the batch, and it is
sent again after one interval with the same `Idempotency-Key` and the same body. Any other answer
drops it, with a log line. When the buffer is full, the oldest event goes.

## `NewSDKCredential`

```go
keelie.NewSDKCredential(keelie.SDKCredentialOptions{
	KeelieURL, TokenURL, ClientID, ClientSecret string
	Timeout    time.Duration // 10 seconds
	HTTPClient *http.Client  // follows no redirect by default
}) (*keelie.SDKCredential, error)
```

A `KeelieClient` that sends each request to keelie with a token of your SDK credential. It mints the
token with the client credentials grant, keeps it until shortly before it expires, and mints again
on a `401`. Many requests at once share one mint. This is what the Python quickstart's
`SdkCredential` class does; in Go it is part of the module.

`KeelieClient` is one method, so a test or a proxy can give its own:

```go
type KeelieClient interface {
	Send(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error)
}
```

`keelie.KeelieFunc` turns a function into one.

---

## Logs

Each line is one fixed event name and its fields, the same names as in Python. The SDK writes
through `log/slog`: the event name is the message, and its fields are attributes, such as
`msg=apiable.token_rejected reason=expired`. By default warnings go to stderr, and info and debug
lines are dropped. Send them to your own logger:

```go
keelie.SetLogger(slog.Default())
```

| Event | Level | Meaning |
|---|---|---|
| `apiable.token_rejected` | INFO | A token did not verify. `reason` says why. |
| `apiable.scope_refused` | INFO | A token did not carry the scope of a route. |
| `apiable.keys_loaded` | INFO | The SDK fetched the issuer's key set. |
| `apiable.keys_unavailable` | WARN | The SDK holds no key set and could not fetch one. Every token is refused. |
| `apiable.keys_not_refreshed` | WARN | A fetch failed. The keys in hand go on verifying. |
| `apiable.key_skipped` | WARN | The SDK could not load one key of the set, or it is under 2048 bits. The rest of the set loads. |
| `apiable.mcp_refused` | INFO | `MCPGuard` refused a request. |
| `apiable.usage_event_invalid` | WARN | `Record` left out an event that keelie would refuse. |
| `apiable.usage_sent` | DEBUG | A batch was sent. |
| `apiable.usage_not_sent` | WARN | A batch failed and waits for a retry. |
| `apiable.usage_dropped` | WARN | Events were lost: refused by keelie, buffer full, or not sent at shutdown. |
| `apiable.catalog_fetch_failed` | WARN | The SDK could not fetch the catalog. |

No line holds a token, a secret or a value taken from the request.

## Test with no network

`SigningKeys` takes an `*http.Client`, so a test can serve its own key set with an
`http.RoundTripper`:

```go
keys := keelie.NewSigningKeys(issuer, &keelie.SigningKeysOptions{HTTPClient: fakeIssuer.Client()})
verifier, _ := keelie.NewTokenVerifier(issuer, resource, orgID, &keelie.TokenVerifierOptions{Keys: keys})
```

`UsageReporter` and `AICatalog` take any `KeelieClient`, such as a `keelie.KeelieFunc`. To test a
handler of your own with claims, give it a request whose context carries them:
`r.WithContext(nethttp.WithClaims(r.Context(), claims))`. The module's own tests in `go/` do all of
these, with a fake issuer in `go/internal/testkit`.

## Where Go differs from Python

| | Python | Go |
|---|---|---|
| Framework | Any ASGI app | `net/http` middleware, `func(http.Handler) http.Handler`. The core takes plain values for any other server. |
| Scope check on a REST route | `scopes.check()` in each route | `ScopeGuard` on each route, or `scopes.Check()` |
| Route keys | `("GET", "/orders/{order_id}")` | `"GET /v1/orders/{orderId}"`, the `ServeMux` pattern. A `HEAD` sent to a `GET` pattern needs the `GET` scope. |
| The claims | `request.state.apiable_claims` | `nethttp.ClaimsFrom(r)`. `MCPGuard` sets them too. |
| Claim types | `UUID`, `None`, `frozenset`, `datetime` | `string` (`""` for none), `[]string`, `time.Time` |
| Talking to keelie | An `httpx.AsyncClient` with the quickstart's `SdkCredential` | `NewSDKCredential()`, in the module. A `401` mints again unless another request already did. |
| Errors | Raised | Returned. `Challenge()` with a bad code panics. |
| Path comparison | The ASGI path, exactly | Every form a router could route, without case. The metadata and catalog paths pass with no token only as sent. |
| A key set with an RSA key under 2048 bits | Loaded | Skipped, with a log line |
| A key that also publishes private members | Loaded as a private key, or skipped if they are broken | Only `n` and `e` are read |
| Callers waiting on a cold key-set fetch that fails | Each tries again in turn | All are refused with that one failure. The next caller tries again. |
| A caller that stops waiting for the key set | Not possible | `Verify(ctx)` refuses with `keys_unavailable` when `ctx` ends. The fetch goes on. |
| A time claim (`exp`, `nbf`, `iat`) that is not a JSON number | A string of digits is read as a number; another string in `iat` is `not_yet_valid`; `null` or a list in `iat` or `nbf` raises an error the SDK does not catch | Refused as `malformed` |
| Amounts | An `int` or a `Decimal`. Zeros past the sixth place are sent as given. | A decimal string. Zeros past the sixth place are trimmed. An exponent is refused. |
| A field left empty in an event | `outcome_id=""` is refused | `""` means not given. An empty `Unit` is `request`. |
| A name that is not UTF-8 | Not possible | Refused as invalid |
| An MCP body with `NaN` or `Infinity` | Read | Refused, `-32700` |
| An MCP key with a lone surrogate escape | Kept as it is | Read as U+FFFD, so two such keys can be refused as a key given twice |
| An MCP body that cannot be read | No answer | `400`, an empty body |
| An MCP handler that writes nothing | No response, so no event | `net/http` answers `200`, and the call is counted |
| Logs | The `logging` module, logger `apiable`, `event key=value` | `log/slog`, the event as the message and its fields as attributes |
| Shut down | `await reporter.aclose(timeout=10)` | `reporter.Close(ctx)`: until `ctx` ends, or 10 seconds. It returns even if a `KeelieClient` ignores `ctx`. |
| Leeway | `leeway_seconds=0` is none | `Leeway: 0` is the default, 30 seconds. A negative value is none. |
| A resource with a malformed IPv6 host | Some forms, such as `https://[::1]x`, are taken | Refused |
