using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Keelie.AspNetCore;

/// <summary>The Keelie middleware for ASP.NET Core.</summary>
public static class KeelieApplicationBuilderExtensions
{
    /// <summary>The largest MCP request body the guard reads: 4 MiB.</summary>
    public const int DefaultMaxBodyBytes = 4 * 1024 * 1024;

    /// <summary>
    /// The REST adapter: checks the token of every request under your address, and gives the claims
    /// to your endpoints, as <see cref="KeelieHttpContextExtensions.GetKeelieClaims"/>.
    /// </summary>
    /// <remarks>
    /// <code>app.UseKeelieTokenGuard(verifier, metadata);</code>
    /// It does not check the scope. Put <see cref="KeelieEndpointExtensions.RequireKeelieScope"/> on
    /// each endpoint, or call <see cref="ScopeMap.Check"/> in it. An endpoint without either is
    /// authenticated, but it has no scope check.
    /// </remarks>
    /// <exception cref="ArgumentException">The verifier's audience is not the metadata's resource.</exception>
    public static IApplicationBuilder UseKeelieTokenGuard(
        this IApplicationBuilder app,
        TokenVerifier verifier,
        ProtectedResourceMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(app);
        var guard = new Guard(verifier, metadata);
        return app.Use(next => context => guard.InvokeAsync(context, next, (_, ctx) => next(ctx)));
    }

    /// <summary>
    /// The adapter for a Streamable HTTP MCP server: checks the token, the scope of each tool call,
    /// and reports one usage event for each tool call your server accepts.
    /// </summary>
    /// <remarks>
    /// <code>
    /// app.UseKeelieMcpGuard(verifier, metadata, tools, reporter);
    /// app.MapMcp("/mcp");
    /// </code>
    /// Give the MCP endpoint itself as the <c>resource</c> of <paramref name="metadata"/>: every
    /// <c>POST</c> under it is read as JSON-RPC. The method and the tool name come from the body
    /// only, never from the <c>Mcp-Method</c> or <c>Mcp-Name</c> header.
    /// <list type="bullet">
    /// <item>A <c>tools/call</c> needs the scope you mapped to its tool. A tool that is not in the map
    /// is refused, with <c>403</c> and JSON-RPC error <c>-31001</c>. The answer does not name the
    /// scope.</item>
    /// <item>Every other method passes with no scope check: <c>initialize</c>,
    /// <c>notifications/*</c>, <c>ping</c>, <c>tools/list</c>, <c>resources/*</c> and
    /// <c>prompts/*</c>.</item>
    /// <item><c>GET</c>, <c>HEAD</c> and <c>DELETE</c> pass, and so does a CORS preflight. Every other
    /// method gets <c>405</c>, with <c>Allow: GET, POST, DELETE</c>.</item>
    /// <item>A body that is not UTF-8 JSON, or is nested too deeply: <c>400</c>, <c>-32700</c>. A batch,
    /// a body that is not an object, a key given twice, or a <c>tools/call</c> with no <c>id</c>:
    /// <c>400</c>, <c>-32600</c>. A <c>tools/call</c> whose <c>params.name</c> is not a string:
    /// <c>400</c>, <c>-32602</c>. A body over <paramref name="maxBodyBytes"/>: <c>413</c>,
    /// <c>-32600</c>.</item>
    /// </list>
    /// The usage event is recorded when your server starts a <c>2xx</c> response, so a
    /// <c>text/event-stream</c> reply streams through unbuffered. The event carries no credits.
    /// </remarks>
    /// <param name="app">The app.</param>
    /// <param name="verifier">The verifier, whose audience is the MCP endpoint.</param>
    /// <param name="metadata">The metadata of the MCP endpoint.</param>
    /// <param name="tools">Each tool name and the one scope it requires, such as <c>["get_order"] = "orders:read"</c>.</param>
    /// <param name="reporter">The process's one usage reporter.</param>
    /// <param name="maxBodyBytes">The largest body it reads. 4 MiB.</param>
    /// <exception cref="ArgumentException">The verifier's audience is not the metadata's resource, or a tool's scope is not one scope.</exception>
    public static IApplicationBuilder UseKeelieMcpGuard(
        this IApplicationBuilder app,
        TokenVerifier verifier,
        ProtectedResourceMetadata metadata,
        IReadOnlyDictionary<string, string> tools,
        UsageReporter reporter,
        int maxBodyBytes = DefaultMaxBodyBytes)
    {
        ArgumentNullException.ThrowIfNull(app);
        var guard = new McpGuard(new Guard(verifier, metadata), tools, reporter, maxBodyBytes);
        return app.Use(next => context => guard.InvokeAsync(context, next));
    }

    /// <summary>
    /// Serves your AI Catalog at <c>/.well-known/ard.json</c> and <c>/.well-known/ai-catalog.json</c>,
    /// with no token. Other requests pass untouched.
    /// </summary>
    /// <remarks>
    /// <code>app.UseKeelieAiCatalog(new AiCatalog(keelie, metadata));</code>
    /// The order beside the token guards does not matter: once the catalog is made with
    /// <c>metadata</c>, the guards let a GET or a HEAD of its two paths pass.
    /// </remarks>
    public static IApplicationBuilder UseKeelieAiCatalog(this IApplicationBuilder app, AiCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(catalog);
        return app.Use(next => async context =>
        {
            var method = context.Request.Method;
            var path = Guard.FullPath(context.Request);
            if (method is not ("GET" or "HEAD") || !AiCatalog.MediaTypes.ContainsKey(path))
            {
                await next(context).ConfigureAwait(false);
                return;
            }
            var answer = await catalog.AnswerAsync(path).ConfigureAwait(false);
            if (answer is null)
            {
                await next(context).ConfigureAwait(false);
                return;
            }
            await Guard.Respond(context, answer.Status, answer.Headers.ToArray(), answer.Body.ToArray()).ConfigureAwait(false);
        });
    }
}
