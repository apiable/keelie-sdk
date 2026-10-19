# Keelie SDK

**Keelie by Apiable.** You, the Provider, install this library in your own API to sell it. It checks
tokens and scopes inside your own process, and it reports usage.

> **Status: in development. The code here is not released, and it has no stable API yet.**
> The first release is for Python and any ASGI framework, such as FastAPI. Other languages follow.
> Everything that ships is published here, under the Apache License 2.0, so that you can read what
> runs in your process instead of taking our word for it.

## Documentation

| Page | What it holds |
|---|---|
| [Quickstart](docs/quickstart.md) | From signup to a protected route, on one page. |
| [Python SDK reference](docs/python.md) | Every class, its arguments, its return value and its errors. |
| [When keelie is down](docs/when-keelie-is-down.md) | What the SDK does in each failure. |

**You can use keelie without this SDK.** The token is a standard JWT, and the usage API is plain
HTTP. Check tokens with the JWT library or the gateway you already have, and report usage from any
language. Both follow the published keelie contract:
<https://raw.githubusercontent.com/apiable/keelie-sdk/contract/openapi/keelie.json> and the
[token rules](https://github.com/apiable/keelie-sdk/blob/contract/docs/token-rules.md), published
with each keelie release.

## What it does

- **Check each token inside your process.** The SDK verifies a token against the issuer's key set,
  which it fetches and caches. It never asks Apiable for a verdict on a request.
- **Apply the scopes of the plan** on each route of your API.
- **Report usage in batches, after the response.** A failed report never stops a request. A failed
  token check does, and that check is local.

## What it never does

- **It is not in the path of your API call.** Your requests do not pass through Apiable. Nothing
  in this SDK forwards, proxies or terminates them.
- **What Apiable charges you never comes from what this SDK reports.** It comes only from what
  Apiable sees at its own endpoints. The usage this SDK reports feeds your dashboards and your
  spend caps.

## Layout

| Folder | What it holds |
|---|---|
| [`python/`](python/) | The Python package `apiable`. On PyPI today it is a placeholder that reserves the name. |
| [`docs/`](docs/) | The documentation. |

## Security

Report a vulnerability privately. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome under the Developer Certificate of Origin. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Apiable Oy.
