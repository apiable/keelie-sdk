# apiable/keelie

**In development. The Keelie SDK for PHP, by Apiable, is not released yet.** The package is not on
Packagist.

## What it is

The PHP package of the Keelie SDK: PSR-15 middleware for Slim, Mezzio and any other framework that
runs PSR-15 middleware, with a guard for an MCP server. Its core takes plain values, so Laravel and
Symfony can call it from their own middleware. Like the Python package, it:

- verifies tokens **inside your own process**, against a key set it fetches and caches, so there is
  no call to Apiable on the request path;
- enforces scopes per route, and per tool on an MCP server;
- reports usage back in batches **after** the response, and never blocks a request if that report
  fails.

A failed usage report does not stop a call. A failed token check does. That check is local.

```php
$app->get('/v1/orders/{id}', $showOrder)
    ->add(new ScopeGuard($scopes, $metadata, $responseFactory, '/v1/orders/{id}'));
$app->add(new TokenGuard($verifier, $metadata, $responseFactory));
```

## Status

In development. PHP 8.2 or later, with ext-curl and ext-openssl. It depends only on the PSR
interfaces: PSR-3, PSR-7, PSR-15, PSR-16 and PSR-17.

Documentation: the [quickstart](https://github.com/apiable/keelie-sdk/blob/main/docs/quickstart.md)
for signup, and the [PHP reference](https://github.com/apiable/keelie-sdk/blob/main/docs/php.md).

Source: <https://github.com/apiable/keelie-sdk>. Progress and early access: <https://apiable.io>.

## Develop

```bash
composer install
composer test   # no network
```

The tests check every edge-case token against the reason the Python SDK gives it, from the same
fixture as the Ruby gem.
