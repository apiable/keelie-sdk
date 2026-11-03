using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Keelie.AspNetCore;

/// <summary>
/// The adapter for a Streamable HTTP MCP server: checks the token, the scope of each tool call, and
/// reports one usage event for each tool call the server accepts.
/// </summary>
internal sealed class McpGuard
{
    // The method of a tool call. It is also the method half of each key in the adapter's ScopeMap:
    // ("tools/call", <tool name>).
    private const string ToolsCall = "tools/call";

    private const int ParseError = -32700;
    private const int InvalidRequest = -32600;
    private const int InvalidParams = -32602;
    // An application code: MCP keeps -32000 to -32099 for itself.
    private const int InsufficientScopeCode = -31001;
    private const string Category = "Keelie.AspNetCore.McpGuard";

    private static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = StrictJson.MaxDepth };

    private readonly Guard _guard;
    private readonly ScopeMap _scopes;
    private readonly UsageReporter _reporter;
    private readonly int _maxBodyBytes;
    private readonly string _scopeRefusal;

    internal McpGuard(Guard guard, IReadOnlyDictionary<string, string> tools, UsageReporter reporter, int maxBodyBytes)
    {
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(reporter);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBodyBytes);
        _guard = guard;
        // Split at the first space, so a tool name is the whole route, spaces and all.
        _scopes = new ScopeMap(tools.Select(tool => KeyValuePair.Create($"{ToolsCall} {tool.Key}", tool.Value)));
        _reporter = reporter;
        _maxBodyBytes = maxBodyBytes;
        _scopeRefusal = guard.Metadata.Challenge("insufficient_scope");
    }

    internal Task InvokeAsync(HttpContext context, RequestDelegate next) =>
        _guard.InvokeAsync(context, next, (claims, ctx) => HandleAsync(claims, ctx, next));

    private async Task HandleAsync(Claims claims, HttpContext context, RequestDelegate next)
    {
        var method = context.Request.Method;
        if (method is "GET" or "HEAD" or "DELETE")
        {
            await next(context).ConfigureAwait(false);
            return;
        }
        if (method != "POST")
        {
            // A body under any other method could carry a tool call: refuse it.
            await Guard.Respond(context, StatusCodes.Status405MethodNotAllowed, [new("Allow", "GET, POST, DELETE")]).ConfigureAwait(false);
            return;
        }

        var body = await ReadBodyAsync(context).ConfigureAwait(false);
        if (body is null)
        {
            return; // the client went away
        }
        if (body.Length > _maxBodyBytes)
        {
            await ErrorAsync(context, StatusCodes.Status413PayloadTooLarge, null, InvalidRequest, "Request body too large").ConfigureAwait(false);
            return;
        }

        switch (StrictJson.Check(body))
        {
            case StrictJson.Outcome.DuplicateKey:
                await ErrorAsync(context, StatusCodes.Status400BadRequest, null, InvalidRequest, "Invalid Request").ConfigureAwait(false);
                return;
            case StrictJson.Outcome.ParseError:
                await ErrorAsync(context, StatusCodes.Status400BadRequest, null, ParseError, "Parse error").ConfigureAwait(false);
                return;
        }

        string? tool = null;
        using (var document = JsonDocument.Parse(body, DocumentOptions))
        {
            var request = document.RootElement;
            if (request.ValueKind != JsonValueKind.Object)
            {
                await ErrorAsync(context, StatusCodes.Status400BadRequest, null, InvalidRequest, "Invalid Request").ConfigureAwait(false);
                return;
            }
            if (request.TryGetProperty("method", out var rpcMethod)
                && rpcMethod.ValueKind == JsonValueKind.String
                && rpcMethod.GetString() == ToolsCall)
            {
                // The id is a string or a whole number, as Python reads one: no point, no exponent.
                if (!request.TryGetProperty("id", out var id)
                    || !(id.ValueKind == JsonValueKind.String
                        || (id.ValueKind == JsonValueKind.Number && !IsDecimalLiteral(id.GetRawText()))))
                {
                    await ErrorAsync(context, StatusCodes.Status400BadRequest, null, InvalidRequest, "Invalid Request").ConfigureAwait(false);
                    return;
                }
                string? name = null;
                if (request.TryGetProperty("params", out var parameters)
                    && parameters.ValueKind == JsonValueKind.Object
                    && parameters.TryGetProperty("name", out var nameElement)
                    && nameElement.ValueKind == JsonValueKind.String)
                {
                    name = nameElement.GetString();
                }
                if (name is null)
                {
                    await ErrorAsync(context, StatusCodes.Status400BadRequest, id, InvalidParams, "Invalid params").ConfigureAwait(false);
                    return;
                }
                try
                {
                    _scopes.Check(claims, ToolsCall, name);
                }
                catch (InsufficientScope)
                {
                    await ErrorAsync(
                        context,
                        StatusCodes.Status403Forbidden,
                        id,
                        InsufficientScopeCode,
                        "Insufficient scope",
                        new("WWW-Authenticate", _scopeRefusal)).ConfigureAwait(false);
                    return;
                }
                tool = name;
            }
        }

        // The server reads the body that was checked, byte for byte.
        context.Request.Body = new MemoryStream(body, writable: false);
        context.Request.ContentLength = body.Length;
        if (tool is not null)
        {
            CountToolCall(context, claims, tool);
        }
        await next(context).ConfigureAwait(false);
    }

    private static bool IsDecimalLiteral(string raw) => raw.IndexOfAny(['.', 'e', 'E']) >= 0;

    /// <summary>The body, read in full, or one byte past the limit. <see langword="null"/> if the client went away.</summary>
    private async Task<byte[]?> ReadBodyAsync(HttpContext context)
    {
        var body = new MemoryStream();
        var buffer = new byte[16 * 1024];
        try
        {
            while (true)
            {
                var read = await context.Request.Body.ReadAsync(buffer, context.RequestAborted).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                body.Write(buffer, 0, read);
                if (body.Length > _maxBodyBytes)
                {
                    break;
                }
            }
        }
        catch (Exception error) when (error is IOException or OperationCanceledException)
        {
            return null;
        }
        return body.ToArray();
    }

    /// <summary>Record one event when the tool call's response starts with 2xx: before its body, so a stream is not held back.</summary>
    private void CountToolCall(HttpContext context, Claims claims, string tool)
    {
        context.Response.OnStarting(() =>
        {
            var status = context.Response.StatusCode;
            if (status is >= 200 and < 300)
            {
                _reporter.Record(claims.Azp, tool, UsageUnit.ToolCall, consumerId: claims.ConsumerId);
            }
            return Task.CompletedTask;
        });
    }

    private static async Task ErrorAsync(
        HttpContext context,
        int status,
        JsonElement? id,
        int code,
        string message,
        KeyValuePair<string, string>? header = null)
    {
        Log.Info(Category, "apiable.mcp_refused status={Status} code={Code}", status, code);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("jsonrpc", "2.0");
            writer.WritePropertyName("id");
            if (id is { ValueKind: JsonValueKind.String } text)
            {
                writer.WriteStringValue(text.GetString());
            }
            else if (id is { ValueKind: JsonValueKind.Number } number)
            {
                var raw = number.GetRawText();
                writer.WriteRawValue(raw == "-0" ? "0" : raw);
            }
            else
            {
                writer.WriteNullValue();
            }
            writer.WriteStartObject("error");
            writer.WriteNumber("code", code);
            writer.WriteString("message", message);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        KeyValuePair<string, string>[] headers = header is { } extra
            ? [extra, new("Content-Type", "application/json")]
            : [new("Content-Type", "application/json")];
        await Guard.Respond(context, status, headers, stream.ToArray()).ConfigureAwait(false);
    }
}

/// <summary>The SDK's log lines, from the adapter.</summary>
internal static class Log
{
    internal static void Info(string category, string message, params object?[] args)
    {
        var logger = KeelieLogging.LoggerFactory?.CreateLogger(category);
        if (logger is null || !logger.IsEnabled(Microsoft.Extensions.Logging.LogLevel.Information))
        {
            return;
        }
#pragma warning disable CA2254 // Each caller passes a constant template.
        Microsoft.Extensions.Logging.LoggerExtensions.Log(logger, Microsoft.Extensions.Logging.LogLevel.Information, message, args);
#pragma warning restore CA2254
    }
}
