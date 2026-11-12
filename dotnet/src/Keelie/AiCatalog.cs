namespace Keelie;

/// <summary>What to answer a <c>GET</c> or a <c>HEAD</c> of a catalog path.</summary>
/// <param name="Status">200, or 503 when keelie did not answer.</param>
/// <param name="Headers">The headers to send, beside <c>Content-Length</c>.</param>
/// <param name="Body">The catalog, or nothing on a 503. Send no body on a <c>HEAD</c>.</param>
public sealed record CatalogAnswer(int Status, IReadOnlyDictionary<string, string> Headers, ReadOnlyMemory<byte> Body);

/// <summary>Options of <see cref="AiCatalog"/>.</summary>
public sealed class AiCatalogOptions
{
    /// <summary>The clock of the cache. <see cref="TimeProvider.System"/> unless you give another.</summary>
    public TimeProvider? TimeProvider { get; init; }
}

/// <summary>
/// Your AI Catalog, fetched from keelie and served from your own domain.
/// </summary>
/// <remarks>
/// The catalog is at <c>/.well-known/ard.json</c>, where ARD v0.91 looks for it, and at
/// <c>/.well-known/ai-catalog.json</c>, where the ai-catalog specification looks and an MCP
/// proposal points. Both paths serve the same body, from the same copy.
/// <para>
/// keelie builds the catalog from your published plans. This class fetches it from keelie with your
/// credential, keeps it for 60 seconds, and serves it with no token. A plan you publish shows here
/// within 60 seconds, and within up to 120 seconds at a client that caches the answer.
/// </para>
/// <para>
/// The SDK does not change the document. It keeps no copy past 60 seconds: if keelie does not
/// answer when the copy is old, the answer is <c>503</c>, not an old catalog. After a failure, it
/// asks keelie again after 10 seconds, not on each request.
/// </para>
/// </remarks>
public sealed class AiCatalog
{
    /// <summary>Where ARD v0.91 looks for the catalog.</summary>
    public const string ArdPath = "/.well-known/ard.json";

    /// <summary>Where the ai-catalog specification looks for the catalog.</summary>
    public const string CatalogPath = "/.well-known/ai-catalog.json";

    /// <summary>The one place that names keelie's catalog endpoint.</summary>
    public const string KeeliePath = "/ai-catalog";

    /// <summary>How long a copy is served.</summary>
    public static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(60);

    /// <summary>How long after a failure keelie is asked again.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The media type of each catalog path. ARD v0.91 names none for <c>ard.json</c>. A GET or a
    /// HEAD of either needs no token, once an <see cref="AiCatalog"/> serves it. This map is the one
    /// list of those paths: the guards and the catalog both read it.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> MediaTypes = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [ArdPath] = "application/json",
        [CatalogPath] = "application/ai-catalog+json",
    };

    private const string Category = "Keelie.AiCatalog";

    private readonly HttpClient _keelie;
    private readonly TimeProvider _time;
    // One fetch for many requests at once: the others read what it got, or its failure.
    private readonly SemaphoreSlim _lock = new(1, 1);
    private volatile byte[]? _body;
    private long _fetchedAt;
    private long? _failedAt;

    /// <summary>
    /// The catalog of the Provider whose credential <paramref name="keelie"/> carries.
    /// </summary>
    /// <param name="keelie">
    /// keelie's address as its <see cref="HttpClient.BaseAddress"/>, and the auth of a credential that
    /// may read products, as for <see cref="UsageReporter"/>. It is not disposed here.
    /// </param>
    /// <param name="metadata">
    /// The metadata your token guard uses. Making the catalog with it tells the guards to let a GET
    /// or a HEAD of the two catalog paths pass with no token.
    /// </param>
    /// <param name="options">The clock, for a test.</param>
    public AiCatalog(HttpClient keelie, ProtectedResourceMetadata metadata, AiCatalogOptions? options = null)
    {
        KeelieHttp.RequireBaseAddress(keelie, nameof(keelie));
        ArgumentNullException.ThrowIfNull(metadata);
        _keelie = keelie;
        _time = options?.TimeProvider ?? TimeProvider.System;
        metadata.ServesAiCatalog = true;
    }

    /// <summary>The answer for <paramref name="path"/>, or <see langword="null"/> if it is not a catalog path.</summary>
    public async Task<CatalogAnswer?> AnswerAsync(string path)
    {
        if (!MediaTypes.TryGetValue(path, out var mediaType))
        {
            return null;
        }
        var body = await CatalogAsync().ConfigureAwait(false);
        if (body is null)
        {
            return new CatalogAnswer(
                503,
                new Dictionary<string, string> { ["Retry-After"] = "10", ["Cache-Control"] = "no-store" },
                ReadOnlyMemory<byte>.Empty);
        }
        return new CatalogAnswer(
            200,
            new Dictionary<string, string> { ["Content-Type"] = mediaType, ["Cache-Control"] = "max-age=60" },
            body);
    }

    /// <summary>The catalog, fetched again when the copy is 60 seconds old. <see langword="null"/> if keelie fails.</summary>
    private async Task<byte[]?> CatalogAsync()
    {
        await _lock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Settled())
            {
                return _body;
            }
            _body = null;
            HttpResponseMessage response;
            try
            {
                response = await _keelie.GetAsync(KeelieHttp.UriFor(_keelie, KeeliePath)).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                // Any client failure is a 503.
                Log.Warn(Category, "apiable.catalog_fetch_failed error={Error}", Log.ErrorName(error));
                _failedAt = _time.GetTimestamp();
                return null;
            }
            using (response)
            {
                if ((int)response.StatusCode != 200)
                {
                    Log.Warn(Category, "apiable.catalog_fetch_failed status={Status}", (int)response.StatusCode);
                    _failedAt = _time.GetTimestamp();
                    return null;
                }
                byte[] body;
                try
                {
                    body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                }
                catch (Exception error)
                {
                    Log.Warn(Category, "apiable.catalog_fetch_failed error={Error}", Log.ErrorName(error));
                    _failedAt = _time.GetTimestamp();
                    return null;
                }
                _body = body;
                _fetchedAt = _time.GetTimestamp();
                _failedAt = null;
                return body;
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>True while the copy is fresh, or while a failure is recent: no fetch is due.</summary>
    private bool Settled()
    {
        if (_failedAt is { } failed)
        {
            return _time.GetElapsedTime(failed) < RetryAfter;
        }
        return _body is not null && _time.GetElapsedTime(_fetchedAt) < CacheDuration;
    }
}
