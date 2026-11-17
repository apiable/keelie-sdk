# keelie

**In development. The Keelie SDK for Node, by Apiable, is not released yet.** The name `keelie` on
npm is held, with no code in it yet.

## What it is

The Node package of the Keelie SDK, with adapters for Express 4 and 5. Like the Python package, it:

- verifies tokens **inside your own process**, against a key set it fetches and caches, so there is
  no call to Apiable on the request path;
- enforces scopes per route, and per tool on an MCP server;
- reports usage back in batches **after** the response, and never blocks a request if that report
  fails.

A failed usage report does not stop a call. A failed token check does. That check is local.

```ts
import { tokenGuard, scopeGuard } from "keelie/express";

app.use(tokenGuard({ verifier, metadata }));
app.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), handler);
```

## Status

In development. Node 22.12 or later.

Documentation: the [quickstart](https://github.com/apiable/keelie-sdk/blob/main/docs/quickstart.md)
for signup, and the [Node reference](https://github.com/apiable/keelie-sdk/blob/main/docs/node.md).

Source: <https://github.com/apiable/keelie-sdk>. Progress and early access: <https://apiable.io>.

## Develop

```bash
npm install
npm test        # compiles, then runs the tests with node:test. No network.
npm run build   # writes dist/
```

The tests run against Express 4 and Express 5, and against the official MCP TypeScript SDK.
