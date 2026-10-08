# Keelie SDK

**Keelie by Apiable.** You, the Provider, install this library in your own API to sell it. It checks
tokens and scopes inside your own process, and it reports usage.

> **Status: in development. This repository holds no SDK code yet.**
> The first release is for Python and FastAPI. Other languages follow. Everything that ships is
> published here, under the Apache License 2.0, so that you can read what runs in your process
> instead of taking our word for it.

## What it will do

- **Check each token inside your process.** The SDK verifies a token against the issuer's key set,
  which it fetches and caches. It never asks Apiable for a verdict on a request.
- **Apply the scopes of the plan** on each route of your API.
- **Report usage in batches, after the response.** A failed report never stops a request. A failed
  token check does, and that check is local.

## What it will never do

- **It is not in the path of your API call.** Your requests do not pass through Apiable. Nothing
  in this SDK forwards, proxies or terminates them.
- **What Apiable charges you never comes from what this SDK reports.** It comes only from what
  Apiable sees at its own endpoints. The usage this SDK reports feeds your dashboards and your
  spend caps.

## Layout

| Folder | What it holds |
|---|---|
| [`python/`](python/) | The Python package `apiable` on PyPI. Today it is a placeholder that reserves the name. |

## Security

Report a vulnerability privately. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome under the Developer Certificate of Origin. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Apiable Oy.
