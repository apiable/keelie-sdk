# Keelie

**In development. The Keelie SDK for .NET, by Apiable, is not released yet.** There is nothing on
NuGet yet.

## What it is

The .NET packages of the Keelie SDK, for .NET 8 and .NET 10:

- `Keelie`, the core, with no web framework in it;
- `Keelie.AspNetCore`, the adapters for ASP.NET Core: a token guard for a REST API, a scope check
  on each endpoint, a guard for a Streamable HTTP MCP server, and the AI Catalog.

Like the Python and Node packages, it:

- verifies tokens **inside your own process**, against a key set it fetches and caches, so there is
  no call to Apiable on the request path;
- enforces scopes per route, and per tool on an MCP server;
- reports usage back in batches **after** the response, and never blocks a request if that report
  fails.

A failed usage report does not stop a call. A failed token check does. That check is local.

```csharp
app.UseKeelieTokenGuard(verifier, metadata);
app.MapGet("/v1/orders/{orderId}", handler).RequireKeelieScope(scopes, metadata);
```

## Status

In development. .NET 8 or .NET 10.

Documentation: the [quickstart](https://github.com/apiable/keelie-sdk/blob/main/docs/quickstart.md)
for signup, and the [.NET reference](https://github.com/apiable/keelie-sdk/blob/main/docs/dotnet.md).

Source: <https://github.com/apiable/keelie-sdk>. Progress and early access: <https://apiable.io>.

## Develop

```bash
dotnet build -warnaserror   # both targets, net8.0 and net10.0
dotnet test                 # no network: fakes in the process, and apps on the loopback address
```

The tests run against ASP.NET Core's own server, Kestrel, and against the official MCP C# SDK, as a
real client and a real server. Every package version is pinned, in `Directory.Packages.props` and
the lock files.
