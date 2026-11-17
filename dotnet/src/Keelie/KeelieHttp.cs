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
}
