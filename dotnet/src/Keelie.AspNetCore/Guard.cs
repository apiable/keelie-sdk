using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Keelie.AspNetCore;

/// <summary>
/// The one token check, which every adapter goes through, and nothing else.
/// </summary>
/// <remarks>
/// Every adapter refuses a token in the same way: <c>401</c>, an empty body, and
/// <c>WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."</c>. The answer is the
/// same for every reason. The reason goes to your log only.
/// <para>
/// It also serves the RFC 9728 metadata at <c>metadata.Path</c>, with no token, and refuses a
/// request with no token with <c>401</c> and <c>WWW-Authenticate: Bearer resource_metadata="..."</c>,
/// so an agent can find your issuer. Paths outside <c>resource</c> and a CORS preflight
/// (<c>OPTIONS</c>) pass untouched.
/// </para>
/// <para>
/// The verifier's audience must be the <c>resource</c> of the metadata, or the guard does not
/// start. An agent asks keelie for a token with that <c>resource</c> (RFC 8707), and keelie writes
/// your org's <c>resource</c> into <c>aud</c>. A verifier for another audience would refuse every
/// such token, or accept a token for another server.
/// </para>
/// </remarks>
internal sealed class Guard
{
    private readonly TokenVerifier _verifier;
    private readonly ProtectedResourceMetadata _metadata;
    private readonly string _challenge;
    private readonly string _refusal;
    private readonly byte[] _document;
    private readonly string[] _prefixes;

    internal Guard(TokenVerifier verifier, ProtectedResourceMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(metadata);
        if (verifier.Audience != metadata.Resource)
        {
            throw new ArgumentException(
                $"the verifier's audience {JsonSerializer.Serialize(verifier.Audience)} is not the resource "
                + $"{JsonSerializer.Serialize(metadata.Resource)}: give both the same value",
                nameof(verifier));
        }
        _verifier = verifier;
        _metadata = metadata;
        _challenge = metadata.Challenge();
        _refusal = metadata.Challenge("invalid_token");
        _document = Encoding.UTF8.GetBytes(metadata.Document);
        _prefixes = Prefixes(metadata.PathPrefix);
    }

    internal ProtectedResourceMetadata Metadata => _metadata;

    /// <summary>
    /// Answers the metadata and a missing or refused token itself. Calls <paramref name="handle"/>
    /// with the claims of a token that verified, and <paramref name="next"/> for a request it does
    /// not guard.
    /// </summary>
    internal async Task InvokeAsync(HttpContext context, RequestDelegate next, Func<Claims, HttpContext, Task> handle)
    {
        var request = context.Request;
        var path = FullPath(request);
        if (path == _metadata.Path && request.Method is "GET" or "HEAD")
        {
            // Before the token check: with a resource at the root, the metadata is under it, and
            // the agent reads it with no token.
            await Respond(context, StatusCodes.Status200OK, [new("Content-Type", "application/json")], _document).ConfigureAwait(false);
            return;
        }
        if (!Guarded(context, path))
        {
            await next(context).ConfigureAwait(false);
            return;
        }
        var token = ProtectedResourceMetadata.BearerToken(request.Headers.Authorization.FirstOrDefault());
        if (token is null)
        {
            await Respond(context, StatusCodes.Status401Unauthorized, [new("WWW-Authenticate", _challenge)]).ConfigureAwait(false);
            return;
        }
        Claims claims;
        try
        {
            claims = await AuthenticateAsync(_verifier, token).ConfigureAwait(false);
        }
        catch (TokenRejected)
        {
            await Respond(context, StatusCodes.Status401Unauthorized, [new("WWW-Authenticate", _refusal)]).ConfigureAwait(false);
            return;
        }
        context.Features.Set(new KeelieClaimsFeature(claims));
        await handle(claims, context).ConfigureAwait(false);
    }

    /// <summary>The claims of the request's Bearer token, or <see cref="TokenRejected"/>.</summary>
    internal static Task<Claims> AuthenticateAsync(TokenVerifier verifier, string token) => verifier.VerifyAsync(token);

    /// <summary>
    /// True for a request under <c>resource</c> that must carry a token.
    /// </summary>
    /// <remarks>
    /// A CORS preflight (<c>OPTIONS</c>) and every path outside <c>resource</c> pass. So does a GET
    /// or a HEAD of the metadata, and of the AI Catalog at either of its paths when the catalog
    /// serves it. Any other method on those paths needs a token.
    /// <para>
    /// The path is compared in every form ASP.NET Core could route it by: with and without the path
    /// base, as Kestrel gives it, as the client sent it, with escapes read, dot segments resolved and
    /// doubled slashes folded, and without case, because ASP.NET Core routes without case. It is
    /// compared with the path of <c>resource</c> and with each tail of it, for a base the app routes
    /// without, or a prefix a proxy strips. A request that is under
    /// <c>resource</c> in any of these forms is guarded. It can only guard more than the router
    /// serves, never less.
    /// </para>
    /// </remarks>
    private bool Guarded(HttpContext context, string path)
    {
        var method = context.Request.Method;
        if (method == "OPTIONS")
        {
            return false;
        }
        if (method is "GET" or "HEAD"
            && (path == _metadata.Path || (_metadata.ServesAiCatalog && AiCatalog.MediaTypes.ContainsKey(path))))
        {
            return false;
        }
        if (_metadata.PathPrefix.Length == 0)
        {
            return true;
        }
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        var forms = PathForms(path, rawTarget).Concat(PathForms(context.Request.Path.Value ?? string.Empty, null));
        foreach (var form in forms)
        {
            foreach (var prefix in _prefixes)
            {
                if (form.Equals(prefix, StringComparison.OrdinalIgnoreCase)
                    || form.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// The path of <c>resource</c>, and each tail of it at a segment boundary: for <c>/api/v1</c>,
    /// <c>/api/v1</c> and <c>/v1</c>. An app behind <c>UsePathBase("/api")</c> routes <c>/v1/...</c>
    /// with no base as well, and an app behind a proxy that strips <c>/api</c> sees only
    /// <c>/v1/...</c>. A request under any tail is guarded, so the guard never sees less of the
    /// resource than the router does.
    /// </summary>
    private static string[] Prefixes(string prefix)
    {
        var prefixes = new List<string> { prefix };
        if (prefix.Length < 2)
        {
            return prefixes.ToArray(); // a resource at the root guards every path already
        }
        for (var at = prefix.IndexOf('/', 1); at > 0; at = prefix.IndexOf('/', at + 1))
        {
            if (at < prefix.Length - 1)
            {
                prefixes.Add(prefix[at..]);
            }
        }
        return prefixes.ToArray();
    }

    /// <summary>The path of the request, with the path base the app was mounted at.</summary>
    internal static string FullPath(HttpRequest request) =>
        request.PathBase.Add(request.Path).Value ?? string.Empty;

    internal static IEnumerable<string> PathForms(string path, string? rawTarget)
    {
        var forms = new HashSet<string>(StringComparer.Ordinal) { path };
        if (rawTarget is { Length: > 0 } && rawTarget[0] == '/')
        {
            var end = rawTarget.IndexOfAny(['?', '#']);
            forms.Add(end < 0 ? rawTarget : rawTarget[..end]);
        }
        // Each pass reads escapes, resolves dot segments and folds slashes. Two passes reach a form
        // that an escape of an escape, or a dot segment made by an escape, would hide.
        for (var pass = 0; pass < 2; pass++)
        {
            foreach (var form in forms.ToArray())
            {
                string decoded;
                try
                {
                    decoded = Uri.UnescapeDataString(form);
                }
                catch (UriFormatException)
                {
                    decoded = form;
                }
                forms.Add(decoded);
                forms.Add(RemoveDotSegments(form));
                forms.Add(RemoveDotSegments(decoded));
                forms.Add(FoldSlashes(form));
                forms.Add(FoldSlashes(decoded));
                forms.Add(RemoveDotSegments(FoldSlashes(decoded)));
            }
        }
        return forms;
    }

    private static string FoldSlashes(string path)
    {
        var builder = new StringBuilder(path.Length);
        foreach (var c in path)
        {
            if (c == '/' && builder.Length > 0 && builder[^1] == '/')
            {
                continue;
            }
            builder.Append(c);
        }
        return builder.ToString();
    }

    /// <summary>RFC 3986, section 5.2.4.</summary>
    private static string RemoveDotSegments(string path)
    {
        var output = new List<string>();
        var segments = path.Split('/');
        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];
            if (segment == ".")
            {
                if (i == segments.Length - 1)
                {
                    output.Add(string.Empty);
                }
                continue;
            }
            if (segment == "..")
            {
                if (output.Count > 1)
                {
                    output.RemoveAt(output.Count - 1);
                }
                if (i == segments.Length - 1)
                {
                    output.Add(string.Empty);
                }
                continue;
            }
            output.Add(segment);
        }
        return string.Join('/', output);
    }

    internal static async Task Respond(HttpContext context, int status, KeyValuePair<string, string>[] headers, byte[]? body = null)
    {
        var response = context.Response;
        response.StatusCode = status;
        foreach (var (name, value) in headers)
        {
            response.Headers[name] = value;
        }
        body ??= [];
        response.ContentLength = body.Length;
        if (body.Length > 0 && !HttpMethods.IsHead(context.Request.Method))
        {
            await response.Body.WriteAsync(body, context.RequestAborted).ConfigureAwait(false);
        }
    }
}

/// <summary>The claims of the request's token, set by a Keelie guard.</summary>
internal sealed class KeelieClaimsFeature(Claims claims)
{
    internal Claims Claims { get; } = claims;
}
