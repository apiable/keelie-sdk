# PHP SDK reference

The PHP package of the Keelie SDK, for PHP 8.2 or later. It is PSR-15 middleware, so it runs under
Slim, Mezzio and any other framework that runs PSR-15 middleware. Its core takes plain values, so
Laravel and Symfony can call it from their own middleware. It does what the Python package does, by
the same rules: it checks each token inside your own process, checks the scope of each route or
tool, and reports usage in batches, after the response. Your requests never pass through Apiable.

> **Status: in development, not released.** The package `apiable/keelie-sdk` is not on Packagist yet.
> Until it is released, install it from this repository (see [Install](#install)).
>
> Packagist reads `composer.json` only from the root of a repository. This package is in `php/`,
> so a release needs a read-only repository that holds only `php/`, kept in sync from this one.
> That repository does not exist yet.

The [quickstart](quickstart.md) covers signup and registering your API's address. Those steps are
the same in every language. This page starts at step 3, with PHP.

| Resource | Location |
|---|---|
| Source | [`php/`](../php/) in this repository |
| PHP | 8.2 or later, with ext-curl and ext-openssl |
| Dependencies | The PSR interfaces only: PSR-3, PSR-7, PSR-15, PSR-16 and PSR-17. It reads JWTs and JSON itself. |
| Frameworks | Any PSR-15 framework, such as Slim 4 and Mezzio. Laravel and Symfony through the core. |

## Install

```bash
git clone https://github.com/apiable/keelie-sdk
```

Then, in your API's folder:

```bash
composer config repositories.keelie path /path/to/keelie-sdk/php
```

```bash
composer require apiable/keelie-sdk:@dev
```

## Get started with Slim

Give your application the values from steps 1 and 2 of the quickstart, from the environment:
`KEELIE_URL`, `KEELIE_TOKEN_URL`, `KEELIE_ISSUER`, `KEELIE_ORG_ID`, `KEELIE_RESOURCE`,
`KEELIE_SDK_CLIENT_ID` and `KEELIE_SDK_CLIENT_SECRET`.

```php
<?php
// public/index.php
use Keelie\Middleware\ScopeGuard;
use Keelie\Middleware\TokenGuard;
use Keelie\ProtectedResourceMetadata;
use Keelie\ScopeMap;
use Keelie\SdkCredential;
use Keelie\SigningKeys;
use Keelie\TokenVerifier;
use Keelie\UsageReporter;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Symfony\Component\Cache\Adapter\ApcuAdapter;
use Symfony\Component\Cache\Psr16Cache;

require __DIR__ . '/../vendor/autoload.php';

function env(string $name): string
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        throw new RuntimeException("{$name} is not set");
    }

    return $value;
}

$cache = new Psr16Cache(new ApcuAdapter('keelie'));
$keelie = new SdkCredential(
    env('KEELIE_URL'),
    env('KEELIE_TOKEN_URL'),
    env('KEELIE_SDK_CLIENT_ID'),
    env('KEELIE_SDK_CLIENT_SECRET'),
    cache: $cache,
);
$keys = new SigningKeys(env('KEELIE_ISSUER'), cache: $cache);
$verifier = new TokenVerifier(env('KEELIE_ISSUER'), env('KEELIE_RESOURCE'), env('KEELIE_ORG_ID'), $keys);
$metadata = new ProtectedResourceMetadata(env('KEELIE_RESOURCE'), env('KEELIE_ISSUER'));
$scopes = new ScopeMap(['GET /v1/orders/{id}' => 'orders:read']);
$reporter = new UsageReporter($keelie);

$app = AppFactory::create();
$responses = $app->getResponseFactory();

$app->get('/v1/orders/{id}', function (Request $request, Response $response, array $args) use ($reporter): Response {
    $claims = TokenGuard::claims($request);
    $reporter->record($claims->azp, 'GET /v1/orders/{id}', credits: 1, consumerId: $claims->consumerId);
    $response->getBody()->write(json_encode(['orderId' => $args['id']]));

    return $response->withHeader('Content-Type', 'application/json');
})->add(new ScopeGuard($scopes, $metadata, $responses, '/v1/orders/{id}'));

$app->add(new TokenGuard($verifier, $metadata, $responses));
$app->run();
```

What each line does:

- `TokenGuard` checks the token of every request under your address. It refuses a missing or bad
  token with `401`, before Slim routes the request, and puts the claims in the request attribute
  `keelie.claims`. `TokenGuard::claims($request)` reads them.
- `ScopeGuard` refuses a token that does not carry the scope of the route, with `403`.
- `$reporter->record` puts one usage event in memory and returns at once. The events go to keelie
  after the response (see [Usage under PHP-FPM](#usage-under-php-fpm)). `credits` is what the call
  costs the Consumer. `consumerId` names the Consumer on a token for a person, whose `azp` is an
  agent's client. On a credential's token it is `null`.
- `$cache` is a PSR-16 cache, here APCu through `symfony/cache`. The processes of PHP-FPM share the
  key set, the token of your SDK credential and the AI Catalog through it. Any PSR-16 cache fits,
  such as Redis. Without a cache, each request fetches the key set again.

Then check it as in steps 6 and 7 of the quickstart.

### Usage under PHP-FPM

PHP-FPM starts each request with empty memory, so the reporter cannot wait 5 seconds for a batch.
When the request ends, the reporter:

1. Ends the response to the client, with `fastcgi_finish_request()`. The client does not wait for
   the report. Laravel and Symfony already do this after they send the response.
2. Sends the events of the request to keelie, in one batch, for at most 10 seconds.

A batch that fails is dropped, with the log line `apiable.usage_dropped ... reason=closed`. Under
PHP-FPM there is no later request to send it again. Usage is telemetry for your dashboards and your
spend caps, never an invoice line, so a lost batch costs no money.

Give `sendAtShutdown: false` to turn this off, and call `$reporter->close()` yourself.

### Usage in a worker

RoadRunner, Swoole, FrankenPHP in worker mode and Laravel Octane serve many requests in one
process. There, call `$reporter->flushIfDue()` after each response. It sends a full batch at once,
the other events after 5 seconds, and a failed batch again after 5 seconds, with the same
idempotency key. Call `$reporter->close()` when the worker stops.

## Laravel and Symfony

Laravel and Symfony do not run PSR-15 middleware themselves. Call the core from their own
middleware. A Laravel route middleware, for a route registered as `/v1/orders/{id}`:

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keelie\InsufficientScope;
use Keelie\ProtectedResourceMetadata;
use Keelie\ScopeMap;
use Keelie\TokenRejected;
use Keelie\TokenVerifier;
use Symfony\Component\HttpFoundation\Response;

final class KeelieGuard
{
    public function __construct(
        private TokenVerifier $verifier,
        private ProtectedResourceMetadata $metadata,
        private ScopeMap $scopes,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $token = ProtectedResourceMetadata::bearerToken($request->header('Authorization'));
        if ($token === null) {
            return response('', 401, ['WWW-Authenticate' => $this->metadata->challenge()]);
        }
        try {
            $claims = $this->verifier->verify($token);
            $this->scopes->check($claims, $request->method(), '/' . $request->route()->uri());
        } catch (TokenRejected) {
            return response('', 401, ['WWW-Authenticate' => $this->metadata->challenge('invalid_token')]);
        } catch (InsufficientScope) {
            return response('', 403, ['WWW-Authenticate' => $this->metadata->challenge('insufficient_scope')]);
        }
        $request->attributes->set('keelie.claims', $claims);

        return $next($request);
    }
}
```

Bind `TokenVerifier`, `ProtectedResourceMetadata`, `ScopeMap` and `UsageReporter` as singletons in
a service provider. Serve `$metadata->document` with `Content-Type: application/json` at
`$metadata->path`, with no token, so that an agent can find your issuer. This middleware is an
example: the package's tests do not run it, and it is not in the package.

In Symfony, make the same calls in a listener of the `kernel.request` event.

## Supported features

| Feature | Where |
|---|---|
| Check a token in your process | `Keelie\TokenVerifier` |
| Check the scope of a route | `Keelie\ScopeMap`, and `Keelie\Middleware\ScopeGuard` on a route |
| Protect a REST API | `Keelie\Middleware\TokenGuard` |
| Protect a Streamable HTTP MCP server | `Keelie\Middleware\McpGuard` |
| Tell an agent where to get a token (RFC 9728) | `Keelie\ProtectedResourceMetadata`, served by each guard |
| Serve your AI Catalog | `Keelie\AiCatalog`, and `Keelie\Middleware\AiCatalogMiddleware` |
| Report usage, and charge an outcome once | `Keelie\UsageReporter` |
| Talk to keelie with your SDK credential | `Keelie\SdkCredential` |

Each middleware takes a PSR-17 response factory, to build the answers it gives itself. Slim gives
one with `$app->getResponseFactory()`. Any other PSR-17 factory fits, such as `nyholm/psr7`.

---

## `Keelie\TokenVerifier`

```php
new TokenVerifier(
    string $issuer,
    string $audience,
    string $orgId,
    ?SigningKeys $keys = null,
    int $leewaySeconds = 30,
)
```

| Argument | Value |
|---|---|
| `$issuer` | `issuer` from the signup answer: your own realm. |
| `$audience` | Your API's address, the `resource` you registered. Every token carries it in `aud`. |
| `$orgId` | `id` from the signup answer. A value that is not a UUID throws `InvalidArgumentException`. |
| `$keys` | The key set. Give one with a PSR-16 cache under PHP-FPM (see [`SigningKeys`](#keeliesigningkeys)). |

### `$verifier->verify(string $token): Claims`

Throws `Keelie\TokenRejected` for every token that does not verify. Its `$reason` is one of
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

Each edge-case token gets the reason the Python SDK gives it. The tests check this against the same
fixture as the Ruby gem: more than 100 tokens, read with PyJWT.

### `$verifier->status(): Status`

What the SDK knows of the issuer, from its last fetch of the key set, as in Python. It makes no
network call. `Keelie\Status` is an enum, and its `value` is the Python string.

| Value | Meaning |
|---|---|
| `Status::Connected` | The last fetch worked. |
| `Status::Degraded` | The last fetch failed. The keys in hand go on verifying. |
| `Status::Offline` | No key in hand. Every token is refused. A new process is offline until the first token fetches the key set. |

### `Keelie\Claims`

Read-only properties.

| Property | Type | Value |
|---|---|---|
| `azp` | `string` | The client id of the Consumer's credential. Report usage with it. |
| `orgId` | `string` | Your org id, lowercase with hyphens. |
| `scopes` | `list<string>` | The scopes of the token, each once. `hasScope('orders:read')` checks one. |
| `jti` | `?string` | The token id. Log it. Never log the token. |
| `expiresAt` | `DateTimeImmutable` | When the token expires, from `exp`, in UTC. |
| `consumerId` | `?string` | On a token for a person, the Consumer whose credits the person uses, lowercase with hyphens. `null` on a credential's token. Report usage with it. |

## `Keelie\SigningKeys`

```php
new SigningKeys(
    string $issuer,
    ?Transport $http = null,
    ?CacheInterface $cache = null,
)
```

The issuer's key set, as in Python. The first token fetches it: the issuer's discovery document
names its `jwks_uri`. A `kid` the SDK does not know fetches the set once more, at most once a
minute. A redirect is not followed: the fetch fails, as a network error does.

**Give a `$cache` under PHP-FPM.** Each request starts with empty memory. Without a cache, each
request fetches the discovery document and the key set again. With a PSR-16 cache, the processes
share one key set and one fetch a minute. The cache holds the public keys and the time of the last
fetch. It holds nothing secret. A failed read or write of the cache is logged, and the SDK goes on
without it.

---

## `Keelie\ScopeMap`

```php
new ScopeMap(array $routes)
```

`$routes` maps `"METHOD /template"` to one scope, such as `['GET /v1/orders/{id}' => 'orders:read']`.
Give the template your router matched, as you wrote it, not the path of the request.

Throws `InvalidArgumentException` when a key is not a method and a template, a value is not exactly
one scope, or a route is given twice.

### `$scopes->check(Claims $claims, string $method, string $route): void`

Returns when the token may call the route. Throws `Keelie\InsufficientScope` when the token does not
carry the scope of the route, or the route is not in the map. The check is strict: a scope matches
only itself, and a route matches only itself. Answer `InsufficientScope` with `403`.

## `Keelie\Middleware\TokenGuard`

```php
$app->add(new TokenGuard($verifier, $metadata, $responseFactory));
```

| Request | Answer |
|---|---|
| `GET` or `HEAD` of the metadata address | `200`, the metadata. No token is needed. |
| No Bearer token, or two `Authorization` headers | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| A token that does not verify | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`, an empty body. The same answer for every reason. |
| A token that verifies | Your app, with the claims in the request attribute `keelie.claims`. |
| A path outside your address, or a CORS preflight (`OPTIONS`) | Your app, untouched. |

It compares the path in every form a router could route it by: as sent, with escapes read, with
dot segments resolved, with doubled slashes folded, without a format extension such as `.json`, and
without case. It can only guard more than your router serves, never less.

The verifier's `audience` must be the `resource` of the metadata, or `TokenGuard` throws
`InvalidArgumentException` when you make it.

`TokenGuard::claims(ServerRequestInterface $request): Claims` reads the claims in a route. It throws
`LogicException` when no guard checked the request.

## `Keelie\Middleware\ScopeGuard`

```php
$app->get('/v1/orders/{id}', $handler)
    ->add(new ScopeGuard($scopes, $metadata, $responseFactory, '/v1/orders/{id}'));
```

Checks the route it is on. Give the route's template, as it is in the `ScopeMap`. The method is the
request's. A refused token gets `403`,
`WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="..."` and an empty body.

Most routers answer a `HEAD` with the route's `GET` handler. So `ScopeGuard` checks a `HEAD` as a
`GET` when the map has no `HEAD` entry for the route.

`TokenGuard` must run first. Without its claims, `ScopeGuard` throws `LogicException`, so the mistake
shows as a `500`.

---

## `Keelie\Middleware\McpGuard`

```php
$app->add(new McpGuard(
    $verifier,
    $metadata,
    $responseFactory,
    $streamFactory,
    tools: ['classify' => 'classify:run'],
    reporter: $reporter,
    maxBodyBytes: 4 * 1024 * 1024,
));
```

| Argument | Value |
|---|---|
| `$streamFactory` | A PSR-17 stream factory. The guard gives your server the body it checked, in a new stream. |
| `$tools` | Each tool name and the one scope it requires. A tool that is not here is refused. |
| `$reporter` | The process's one `UsageReporter`. |
| `$maxBodyBytes` | The largest body it reads. 4 MiB. |

Give the MCP endpoint itself as the `resource` of the metadata, such as
`https://api.example.com/mcp`. Add it before any middleware that parses the body.

It answers as the Python `McpGuard` does:

| Request | Answer |
|---|---|
| A `tools/call` whose tool's scope the token carries | Your server. One `tool_call` event is recorded when your server returns a `2xx` response. |
| A `tools/call` whose tool's scope the token lacks, or that is not mapped | `403`, JSON-RPC `-31001`, `WWW-Authenticate: Bearer error="insufficient_scope"`. The answer does not name the scope. |
| Any other JSON-RPC method | Your server, with no scope check. |
| A body that is not UTF-8 JSON, or is nested too deeply | `400`, `-32700` |
| A batch (an array), a body that is not an object, a key given twice, or a `tools/call` with no `id` | `400`, `-32600` |
| A `tools/call` whose `params.name` is not a string | `400`, `-32602` |
| A body over `maxBodyBytes` | `413`, `-32600` |
| `GET`, `HEAD` or `DELETE` | Your server. |
| Any other method | `405`, `Allow: GET, POST, DELETE` |

---

## `Keelie\ProtectedResourceMetadata`

```php
new ProtectedResourceMetadata(string $resource, string $authorizationServer, ?array $scopesSupported = null)
```

`$resource` is your API's address, exactly as registered: `https`, a lowercase host, no query,
fragment or final slash. `$authorizationServer` is your issuer. Each guard serves the document at
`$metadata->path`, such as `/.well-known/oauth-protected-resource/v1`.

`$metadata->challenge(?string $error = null)` gives the `WWW-Authenticate` value, for a refusal you
answer yourself. `ProtectedResourceMetadata::bearerToken(?string $authorization)` reads the token
from an `Authorization` header value, and does not check it.

## `Keelie\AiCatalog`

```php
$catalog = new AiCatalog($keelie, $metadata, cache: $cache);
$app->add(new AiCatalogMiddleware($catalog, $responseFactory));
```

Serves your AI Catalog at `/.well-known/ard.json` and `/.well-known/ai-catalog.json`, with no
token, as in Python. It fetches the catalog from keelie with your SDK credential and keeps it for
60 seconds. If keelie does not answer when the copy is old, the answer is `503` with
`Retry-After: 10`, never an old catalog. Give a `$cache` under PHP-FPM, so that the processes share
one copy.

`$catalog->answer(string $path): ?CatalogAnswer` gives the answer for another server: a status,
headers and a body, or `null` for a path that is not a catalog path.

---

## `Keelie\UsageReporter`

```php
new UsageReporter(
    KeelieClient $keelie,
    int $batchSize = 50,              // at most 1000
    float $flushIntervalSeconds = 5.0,
    int $maxBufferedEvents = 10000,
    bool $sendAtShutdown = true,
)
```

Make one reporter for the process.

### `$reporter->record(string $clientId, string $capabilityKey, ...): void`

| Argument | Value |
|---|---|
| `unit` | `'request'` (the default), `'tool_call'`, `'token'` or `'outcome'`. |
| `quantity` | How many units. 1. |
| `credits` | What the call costs the Consumer's balance. Leave it out when the call is free. |
| `outcomeId` | The ID of the outcome of a `unit: 'outcome'` event. keelie charges it once. |
| `consumerId` | `$claims->consumerId`. Always pass it. |

An amount is an `int`, a `float`, or a string that holds a whole number or a decimal with at most
six places, such as `'0.25'`. Use a string for exact cents: a `float` cannot hold every decimal
exactly. Zeros past the sixth place are dropped: `'0.0000010'` is sent as `0.000001`.

It does no I/O. An event keelie would refuse is left out, with the log line
`apiable.usage_event_invalid reason=...`. An argument of the wrong PHP type throws `TypeError`, as
in any PHP function.

An outcome's key is `uuid5("a29fa190-9b27-5a07-a1ba-3a0902a3bdcc", outcomeId)`, the same key the
other SDKs make, so one outcome reported from two languages is still charged once.

### `$reporter->flushIfDue(): void`

For a worker that serves many requests. Sends a full batch, events older than one interval, and a
failed batch one interval after it failed. It never throws.

### `$reporter->flush(): void`

Sends every event now, unless a batch failed less than one interval ago. It never throws.

### `$reporter->close(float $timeoutSeconds = 10.0): void`

Sends what is in the buffer, once, and takes no more events. What it cannot send is lost, with one
log line. It never throws. The reporter calls it when PHP shuts down, unless you gave
`sendAtShutdown: false`.

### What happens to a batch

As in Python. A network error, a `401`, `408`, `409`, `429` or a `5xx` keeps the batch, and it is
sent again after one interval with the same `Idempotency-Key` and the same body. Any other answer
drops it, with a log line. When the buffer is full, the oldest event goes. Under PHP-FPM, a batch
that fails at the end of the request is dropped (see [Usage under PHP-FPM](#usage-under-php-fpm)).

## `Keelie\SdkCredential`

```php
new SdkCredential(
    string $keelieUrl,
    string $tokenUrl,
    string $clientId,
    string $clientSecret,
    float $timeoutSeconds = 10.0,
    ?Transport $http = null,
    ?CacheInterface $cache = null,
)
```

Sends each request to keelie with a token of your SDK credential. It mints the token with the
client credentials grant, keeps it until shortly before it expires, and mints again on a `401`.
It follows no redirect, from the token endpoint or from keelie: a `307` or `308` would send the
secret or the token on to another address. A redirect fails the request.

Give a `$cache` under PHP-FPM, so that the processes share one token. The cache then holds the
token, which may report usage and read your products until it expires. It never holds the secret.
The secret stays out of `var_dump()` and `print_r()`.

---

## Logs

Each line is one fixed event name and its fields, the same names as in Python, such as
`apiable.token_rejected reason=expired`. No line holds a token, a secret or a value taken from the
request. By default warnings go to PHP's `error_log()`, and `info` and `debug` are dropped. Send them
to your own PSR-3 logger, such as Monolog or the logger of your framework:

```php
Keelie\Log::setLogger($logger);
```

| Event | Level | Meaning |
|---|---|---|
| `apiable.token_rejected reason=...` | info | A token did not verify. |
| `apiable.scope_refused` | info | A token did not carry the scope of a route. |
| `apiable.keys_loaded` | info | The SDK fetched the issuer's key set. |
| `apiable.keys_unavailable` | warning | The SDK holds no key set and could not fetch one. Every token is refused. |
| `apiable.keys_not_refreshed` | warning | A fetch failed. The keys in hand go on verifying. |
| `apiable.key_skipped` | warning | The SDK could not load one key of the set, or the key is under 2048 bits. The rest of the set loads. |
| `apiable.cache_failed` | warning | A read or a write of your PSR-16 cache failed. The SDK goes on without it. |
| `apiable.mcp_refused` | info | `McpGuard` refused a request. |
| `apiable.usage_event_invalid reason=...` | warning | `record` left out an event that keelie would refuse. |
| `apiable.usage_sent` | debug | keelie took a batch. |
| `apiable.usage_not_sent` | warning | A batch failed and waits for a retry. |
| `apiable.usage_flush_failed` | warning | A flush met an error. The batch waits for a retry. |
| `apiable.usage_dropped` | warning | Events were lost: refused by keelie, buffer full, or not sent at shutdown. |
| `apiable.catalog_fetch_failed` | warning | The SDK could not fetch the catalog. |

## Test with no network

Every network call of the SDK goes through a `Keelie\Http\Transport`: one method,
`send(string $method, string $url, array $headers = [], ?string $body = null): Response`. Give your
own to the objects you make:

```php
$keys = new SigningKeys($issuer, $fakeIssuer);
$verifier = new TokenVerifier($issuer, $resource, $orgId, $keys);
$keelie = new SdkCredential($keelieUrl, $tokenUrl, $clientId, $clientSecret, http: $fakeKeelie);
```

`UsageReporter` and `AiCatalog` take any `Keelie\KeelieClient`, as `SdkCredential` is. The
package's own tests in `php/tests/` do all of these. To test a refusal, sign a token with another
key, or with `exp` in the past.

## Where PHP differs from Python

| | Python | PHP |
|---|---|---|
| Framework | Any ASGI app | Any PSR-15 app, such as Slim and Mezzio. Laravel and Symfony through the core. |
| Calls | `async`: `await verifier.verify(token)` | Plain calls |
| Scope check on a REST route | `scopes.check()` in each route | `ScopeGuard` on each route, or `$scopes->check()` |
| Route keys | `("GET", "/orders/{order_id}")` | `'GET /orders/{id}'` |
| The claims | `request.state.apiable_claims` | The request attribute `keelie.claims`, and `TokenGuard::claims($request)` |
| Claim types | `UUID`, `frozenset`, `datetime` | `string` (lowercase with hyphens), `list<string>`, `DateTimeImmutable` in UTC |
| Status | Strings, such as `"connected"` | The enum `Keelie\Status`, whose `value` is the Python string |
| Talking to keelie | An `httpx.AsyncClient` with the quickstart's `SdkCredential` | `Keelie\SdkCredential`, in the package |
| State between requests | One process holds it | Under PHP-FPM, a PSR-16 cache you give. Without it, each request fetches the key set again. |
| Background work | An asyncio task. `start()` in the lifespan, `await aclose()` at shutdown | None. Under PHP-FPM the events go when the request ends, after the response. In a worker, `flushIfDue()` after each response. |
| A batch that fails | Sent again after one interval | The same in a worker. Under PHP-FPM, dropped when the request ends, with a log line. |
| Amounts | `int` or `Decimal`. `Decimal("1.50")` is sent as `"1.50"` | `int`, `float` or `string`. `'1.50'` is sent as `"1.50"`. |
| Path comparison | As the ASGI server gives it | Every form a router could route, without case, as in Node and Ruby |
| A `resource` that ends in an empty query or fragment, such as `https://api.example.com/v1?` | Accepted | Refused, as in Node |
| An RSA key under 2048 bits in the key set | Loaded | Skipped, with a log line, as in Node |
| JSON nested deeply in a token or an MCP body | Refused at Python's recursion limit | Refused deeper than 1000, as in Ruby |
| A lone surrogate in a token's JSON, such as `"\ud800"` | Read | Refused as `malformed`, as in Ruby |
| When a tool call is counted | When the server starts a `2xx` response | When your server returns a `2xx` response |
| Logs | The `logging` module, logger `apiable` | `Keelie\Log::setLogger()`, any PSR-3 logger. The same event names. |
