# apiable

**Placeholder. The Keelie SDK, by Apiable, is not released yet.**

This package reserves the name while the SDK is in development. Installing it gives you nothing
useful today, and importing anything from it raises `NotImplementedError` with a pointer to this
note rather than a confusing error.

## What it will be

A FastAPI dependency that:

- verifies tokens **inside your own process**, against a key set it fetches and caches, so there is
  no call to Apiable on the request path;
- enforces scopes per route;
- reports usage back in batches **after** the response, and never blocks a request if that report
  fails.

A failed usage report does not stop a call. A failed token check does. That check is local.

## Status

In development. Python and FastAPI first; other languages follow.

Source: <https://github.com/apiable/keelie-sdk>. Progress and early access: <https://apiable.io>.
