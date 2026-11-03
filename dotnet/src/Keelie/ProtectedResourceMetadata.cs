using System.Text;
using System.Text.Json;

namespace Keelie;

/// <summary>
/// The RFC 9728 metadata of your API, and the challenge that points to it.
/// </summary>
/// <remarks>
/// Two standard pieces tell an agent where to get a token for your API, served from your own
/// domain:
/// <list type="bullet">
/// <item>The protected resource metadata (RFC 9728). It names your API and the one issuer that
/// mints tokens for it. An agent reads it at the well-known address of your API. For
/// <c>https://api.example.com/mcp</c> that is
/// <c>https://api.example.com/.well-known/oauth-protected-resource/mcp</c>.</item>
/// <item>A <c>401</c> with <c>WWW-Authenticate: Bearer resource_metadata="..."</c> on a request
/// that carries no token (RFC 6750, RFC 9728 section 5). An agent finds the metadata from this
/// refusal.</item>
/// </list>
/// <para>
/// <c>resource</c> is the URL an agent types for your API, exactly, path included. The metadata
/// repeats it as it is. <c>authorizationServer</c> is the issuer, the same value you give
/// <see cref="TokenVerifier"/>. It is one issuer: an agent uses the first and does not try a
/// second.
/// </para>
/// </remarks>
public sealed class ProtectedResourceMetadata
{
    /// <summary>The well-known path of the metadata, before the path of the resource.</summary>
    public const string WellKnown = "/.well-known/oauth-protected-resource";

    /// <summary>
    /// The resource metadata of <paramref name="resource"/>, whose tokens
    /// <paramref name="authorizationServer"/> mints. <paramref name="scopesSupported"/> is published
    /// only if you give it.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// An address is not https, has no host, has a user, a query, a fragment or a final slash, or an
    /// uppercase scheme or host; or a scope is not exactly one scope.
    /// </exception>
    public ProtectedResourceMetadata(string resource, string authorizationServer, IEnumerable<string>? scopesSupported = null)
    {
        var parts = HttpsUrl("resource", resource);
        var issuer = HttpsUrl("authorizationServer", authorizationServer).Url;
        Resource = parts.Url;
        // The well-known name goes between the host and the path (RFC 9728 section 3.1).
        PathPrefix = parts.Path is "" or "/" ? string.Empty : parts.Path.TrimEnd('/');
        Path = WellKnown + PathPrefix;
        // From the configuration, never from the request's Host.
        Url = $"https://{parts.Netloc}{Path}";

        var document = new StringBuilder("{\"resource\":");
        Compat.WriteJsonString(document, Resource);
        document.Append(",\"authorization_servers\":[");
        Compat.WriteJsonString(document, issuer);
        document.Append("],\"bearer_methods_supported\":[\"header\"]");
        if (scopesSupported is not null)
        {
            var scopes = scopesSupported.ToArray();
            if (!scopes.All(Compat.IsOneScope))
            {
                throw new ArgumentException($"not one scope each: {JsonSerializer.Serialize(scopes)}", nameof(scopesSupported));
            }
            document.Append(",\"scopes_supported\":[");
            for (var i = 0; i < scopes.Length; i++)
            {
                if (i > 0)
                {
                    document.Append(',');
                }
                Compat.WriteJsonString(document, scopes[i]);
            }
            document.Append(']');
        }
        document.Append('}');
        Document = document.ToString();
    }

    /// <summary>Your API's address, as given.</summary>
    public string Resource { get; }

    /// <summary>Where the metadata is served on your host, such as <c>/.well-known/oauth-protected-resource/v1</c>.</summary>
    public string Path { get; }

    /// <summary>The full URL of the metadata, from the configuration, never from the request's Host.</summary>
    public string Url { get; }

    /// <summary>The path of <see cref="Resource"/> with no final slash, such as <c>/v1</c>. Empty for a resource at the root.</summary>
    public string PathPrefix { get; }

    /// <summary>The JSON document, as served.</summary>
    public string Document { get; }

    /// <summary>
    /// True once an <see cref="AiCatalog"/> is made with this metadata. Until then the guards check
    /// a token on the catalog paths like on any other.
    /// </summary>
    public bool ServesAiCatalog { get; internal set; }

    /// <summary>
    /// The <c>WWW-Authenticate</c> value. Give <c>"invalid_token"</c> for a refused token, or
    /// <c>"insufficient_scope"</c> for a refused scope.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="error"/> is not an RFC 6750 error code.</exception>
    public string Challenge(string? error = null)
    {
        if (error is null)
        {
            return $"Bearer resource_metadata=\"{Url}\"";
        }
        if (error.Length == 0 || !error.All(c => c is (>= 'a' and <= 'z') or '_'))
        {
            throw new ArgumentException($"not an RFC 6750 error code: {JsonSerializer.Serialize(error)}", nameof(error));
        }
        return $"Bearer error=\"{error}\", resource_metadata=\"{Url}\"";
    }

    /// <summary>True for the path of <see cref="Resource"/> and every path below it.</summary>
    public bool Protects(string path) =>
        PathPrefix.Length == 0 || path == PathPrefix || path.StartsWith(PathPrefix + "/", StringComparison.Ordinal);

    /// <summary>
    /// The Bearer token in an <c>Authorization</c> header value, or <see langword="null"/>. The
    /// token is not checked.
    /// </summary>
    public static string? BearerToken(string? authorization)
    {
        if (authorization is null)
        {
            return null;
        }
        var value = Compat.Strip(authorization);
        var at = value.IndexOf(' ', StringComparison.Ordinal);
        var scheme = at < 0 ? value : value[..at];
        var token = at < 0 ? string.Empty : Compat.Strip(value[(at + 1)..]);
        return scheme.Equals("bearer", StringComparison.OrdinalIgnoreCase) && token.Length > 0 ? token : null;
    }

    /// <summary>
    /// The value, if it is an https URL with a host and no user, query, fragment or final slash.
    /// The scheme and the host must be lowercase: an uppercase one is refused, not folded. keelie
    /// stores your <c>resource</c> with the same rule and puts it into <c>aud</c> exactly, so the
    /// value here and the <c>aud</c> of a token compare equal.
    /// </summary>
    private static (string Url, string Netloc, string Path) HttpsUrl(string name, string? value)
    {
        // Printable ASCII with no space, quote or backslash: the URL goes inside a quoted string
        // of the header, as it is.
        if (value is null || value.Length == 0 || !value.All(c => c is >= '!' and <= '~' and not '"' and not '\\'))
        {
            throw new ArgumentException($"{name} is not a URL: {JsonSerializer.Serialize(value)}", name);
        }
        ArgumentException Shape() => new(
            $"{name} must be https, with a host, no user, query, fragment or final slash: {JsonSerializer.Serialize(value)}",
            name);
        if (!value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || value.Contains('?') || value.Contains('#'))
        {
            throw Shape();
        }
        var rest = value["https://".Length..];
        var slash = rest.IndexOf('/', StringComparison.Ordinal);
        var netloc = slash < 0 ? rest : rest[..slash];
        var path = slash < 0 ? string.Empty : rest[slash..];
        if (netloc.Contains('@'))
        {
            throw Shape();
        }
        string host;
        string? port;
        if (netloc.StartsWith('['))
        {
            var close = netloc.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
            {
                throw Shape();
            }
            host = netloc[..(close + 1)];
            var after = netloc[(close + 1)..];
            port = after.Length == 0 ? null : after.StartsWith(':') ? after[1..] : throw Shape();
        }
        else
        {
            var colon = netloc.IndexOf(':', StringComparison.Ordinal);
            host = colon < 0 ? netloc : netloc[..colon];
            port = colon < 0 ? null : netloc[(colon + 1)..];
        }
        if (host.Length == 0 || host == "[]")
        {
            throw Shape();
        }
        if (port is { Length: > 0 } && !(port.All(char.IsAsciiDigit) && port.Length <= 5 && int.Parse(port, System.Globalization.CultureInfo.InvariantCulture) <= 65535))
        {
            throw new ArgumentException($"{name} has a port that is not a number: {JsonSerializer.Serialize(value)}", name);
        }
        if (path.Length > 0 && path != "/" && path.EndsWith('/'))
        {
            throw Shape();
        }
        if (!value.StartsWith("https://", StringComparison.Ordinal) || netloc != netloc.ToLowerInvariant())
        {
            throw new ArgumentException($"{name} must have a lowercase scheme and host: {JsonSerializer.Serialize(value)}", name);
        }
        return (value, netloc, path);
    }
}
