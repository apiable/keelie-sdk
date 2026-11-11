# keelie for Go

**In development. The Keelie SDK for Go, by Apiable, is not released yet.** The module
`github.com/apiable/keelie-sdk/go` has no tagged version yet.

## What it is

The Go module of the Keelie SDK, with middleware for `net/http`. Like the Python package, it:

- verifies tokens **inside your own process**, against a key set it fetches and caches, so there is
  no call to Apiable on the request path;
- enforces scopes per route, and per tool on an MCP server;
- reports usage back in batches **after** the response, and never blocks a request if that report
  fails.

A failed usage report does not stop a call. A failed token check does. That check is local.

```go
guard, err := nethttp.TokenGuard(verifier, metadata)
scope := nethttp.ScopeGuard(scopes, metadata)
mux.Handle("GET /v1/orders/{orderId}", scope(http.HandlerFunc(getOrder)))
http.ListenAndServe(":3000", guard(mux))
```

The middleware is a `func(http.Handler) http.Handler`, so it works with `http.ServeMux`, chi and
gorilla/mux. The module has no dependency outside the Go standard library.

## Status

In development. Go 1.24 or later.

Documentation: the [quickstart](https://github.com/apiable/keelie-sdk/blob/main/docs/quickstart.md)
for signup, and the [Go reference](https://github.com/apiable/keelie-sdk/blob/main/docs/go.md).

Source: <https://github.com/apiable/keelie-sdk>. Progress and early access: <https://apiable.io>.

## Develop

```bash
go vet ./...
go test -race ./...                  # the SDK's own tests. No network.
cd mcptest && go test -race ./...    # a real MCP client and server, from the official Go MCP SDK
```

`mcptest/` is a module of its own, so that the SDK has no dependency: the official MCP SDK needs
Go 1.25.
