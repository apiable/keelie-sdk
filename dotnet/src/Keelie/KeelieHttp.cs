namespace Keelie;

/// <summary>How the SDK addresses keelie through the client you give it.</summary>
internal static class KeelieHttp
{
    /// <summary>
    /// keelie's address for <paramref name="path"/>: the client's base address with the path added
    /// after it, as httpx joins them. A relative URI would drop the base address's own path, and
    /// read <c>usage-events:report</c> as a scheme.
    /// </summary>
    internal static Uri UriFor(HttpClient client, string path)
    {
        var baseAddress = client.BaseAddress
            ?? throw new InvalidOperationException("the keelie client has no BaseAddress: set it to KEELIE_URL");
        return new Uri(baseAddress.ToString().TrimEnd('/') + path, UriKind.Absolute);
    }

    internal static void RequireBaseAddress(HttpClient client, string parameter)
    {
        ArgumentNullException.ThrowIfNull(client, parameter);
        if (client.BaseAddress is null || !client.BaseAddress.IsAbsoluteUri)
        {
            throw new ArgumentException("the keelie client needs an absolute BaseAddress: set it to KEELIE_URL", parameter);
        }
    }

    /// <summary>
    /// True for an https URL with a host, and for a plain http URL to a loopback host, for local
    /// development: <c>localhost</c>, <c>127.0.0.1</c> or <c>[::1]</c>, in any case. A URL with a
    /// user is refused. A secret, a token or a key set goes to no other address.
    /// </summary>
    internal static bool IsSecure(Uri? uri) =>
        uri is { IsAbsoluteUri: true, Host.Length: > 0, UserInfo.Length: 0 }
        && (uri.Scheme == Uri.UriSchemeHttps
            || (uri.Scheme == Uri.UriSchemeHttp && uri.Host is "localhost" or "127.0.0.1" or "[::1]"));

    /// <summary>The value as a URI, if <see cref="IsSecure"/> holds for it.</summary>
    /// <exception cref="ArgumentException">It is not an absolute URL, or not https off a loopback host.</exception>
    internal static Uri RequireSecure(string? value, string parameter)
    {
        if (value is null || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || !IsSecure(uri))
        {
            // A URL with a user can hold a password: it stays out of the message.
            var shown = value is null || value.Contains('@', StringComparison.Ordinal) ? "(not shown)" : System.Text.Json.JsonSerializer.Serialize(value);
            throw new ArgumentException(
                $"{parameter} must be an https URL with no user, or http to localhost, 127.0.0.1 or [::1]: {shown}",
                parameter);
        }
        return uri;
    }
}
