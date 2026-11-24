using System.Security.Cryptography;
using System.Text.Json;

namespace Keelie;

/// <summary>What the SDK knows of the issuer, from its last fetch of the key set.</summary>
public enum IssuerStatus
{
    /// <summary>The last fetch worked.</summary>
    Connected,

    /// <summary>The last fetch failed. The keys in hand go on verifying.</summary>
    Degraded,

    /// <summary>No key in hand, so every token is refused.</summary>
    Offline,
}

/// <summary>No key in the set has this <c>kid</c>, after one refresh.</summary>
public sealed class UnknownKey : Exception
{
    /// <summary>A key id that is not in the key set.</summary>
    public UnknownKey(string kid)
        : base(kid)
    {
    }
}

/// <summary>The key set could not be fetched, and no key set is in hand.</summary>
public sealed class KeysUnavailable : Exception
{
    /// <summary>The fetch failed with <paramref name="inner"/>.</summary>
    public KeysUnavailable(Exception inner)
        : base(inner.GetType().Name, inner)
    {
    }
}

/// <summary>Options of <see cref="SigningKeys"/>. Leave them out in production.</summary>
public sealed class SigningKeysOptions
{
    /// <summary>The client that fetches the issuer's documents. One of the SDK's own unless you give another, such as in a test.</summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>The clock of the refresh interval. <see cref="TimeProvider.System"/> unless you give another.</summary>
    public TimeProvider? TimeProvider { get; init; }

    /// <summary>How long the cache refuses a second fetch after one completed. 60 seconds.</summary>
    public TimeSpan RefreshInterval { get; init; } = SigningKeys.DefaultRefreshInterval;
}

/// <summary>
/// The issuer's RS256 signing keys, fetched on first use and refreshed on an unknown <c>kid</c>.
/// </summary>
/// <remarks>
/// The first token fetches the key set: the issuer's discovery document names its
/// <c>jwks_uri</c>, and that document holds the keys. A <c>kid</c> the cache does not know fetches
/// once more, then is refused. That is how a rotated key is picked up without a restart: the first
/// token it signs fetches it.
/// <para>
/// Once a key set is in hand, at most one fetch a minute, however many unknown <c>kid</c> values
/// arrive and whether or not the fetch succeeds. A flood of made-up <c>kid</c> values costs the
/// issuer one request a minute, also while the issuer is down.
/// </para>
/// <para>
/// With no key set in hand, every caller waits for one fetch and gets its outcome. If that fetch
/// fails, each of them is refused, and none fetches again. The failure is kept for 5 seconds: a
/// token in that time is refused at once, and the issuer is not asked. After 5 seconds, the next
/// token fetches again. Each document of a fetch must arrive in full within 5 seconds.
/// </para>
/// <para>
/// A key set with no key the SDK can use is a failed fetch. The keys in hand stay and go on
/// verifying. A key set with at least one usable key replaces the keys in hand, so a key the issuer
/// retires is retired here too.
/// </para>
/// <para>
/// The <c>jwks_uri</c> from the first discovery is kept for the life of the process. The issuer
/// and the <c>jwks_uri</c> must be https. Plain http is allowed only to <c>localhost</c>,
/// <c>127.0.0.1</c> and <c>[::1]</c>, for local development. A discovery
/// document whose <c>issuer</c> is not the configured one is refused, and no key is fetched from it
/// (OpenID Connect Discovery 1.0, section 4.3). Each Provider has its own realm, so each issuer has
/// its own key set: a document of another realm must never fill this one's.
/// </para>
/// </remarks>
public sealed class SigningKeys
{
    /// <summary>The one algorithm the SDK accepts, in the key set and on the token.</summary>
    public const string Algorithm = "RS256";

    /// <summary>How long the cache refuses a second fetch after one completed. Shorter than any token lifetime.</summary>
    public static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromSeconds(60);

    /// <summary>How long one fetch of a document may take, its whole body included.</summary>
    public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(5);

    /// <summary>How long a failed fetch with no key set in hand is kept. The issuer is not asked again before.</summary>
    public static readonly TimeSpan ColdRetryAfter = TimeSpan.FromSeconds(5);

    private const int MinModulusBits = 2048;
    private const string Category = "Keelie.SigningKeys";

    // Redirects are not followed, as in the Python SDK: the issuer answers at its own address.
    private static readonly HttpClient SharedClient = new(new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5) })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    private readonly string _issuer;
    private readonly HttpClient _client;
    private readonly TimeProvider _time;
    private readonly TimeSpan _interval;
    // Every caller that finds the cache cold, or its kid missing, waits here. The issuer answers
    // one request, not one for each caller.
    private readonly SemaphoreSlim _lock = new(1, 1);
    // The last cold fetch that failed: its error, when, and how many have failed. A caller that
    // waited while one failed gets its outcome, and does not fetch again. Written under the lock.
    private Exception? _coldError;
    private long _coldFailedAt;
    private int _coldFailures;
    private volatile IReadOnlyDictionary<string, RSAParameters> _keys = new Dictionary<string, RSAParameters>();
    private string? _jwksUri;
    private long? _fetchedAt;
    private volatile bool _refreshFailed;

    /// <summary>The key set of <paramref name="issuer"/>, fetched on first use.</summary>
    public SigningKeys(string issuer, SigningKeysOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        KeelieHttp.RequireSecure(issuer, nameof(issuer));
        _issuer = issuer.TrimEnd('/');
        _client = options?.HttpClient ?? SharedClient;
        _time = options?.TimeProvider ?? TimeProvider.System;
        _interval = options?.RefreshInterval ?? DefaultRefreshInterval;
    }

    /// <summary>
    /// The key with this id, fetching the set once if it is not there.
    /// </summary>
    /// <exception cref="UnknownKey">No key has this id, after one fetch.</exception>
    /// <exception cref="KeysUnavailable">No key set is in hand, and the fetch failed, now or in the last 5 seconds.</exception>
    public async Task<RSAParameters> GetKeyAsync(string kid)
    {
        if (_keys.TryGetValue(kid, out var known))
        {
            return known;
        }
        var failuresBefore = Volatile.Read(ref _coldFailures);
        await _lock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_keys.ContainsKey(kid))
            {
                if (_fetchedAt is null && _coldError is { } error
                    && (_coldFailures != failuresBefore || _time.GetElapsedTime(_coldFailedAt) < ColdRetryAfter))
                {
                    // Cold, and a fetch failed while this caller waited, or a moment ago: its
                    // outcome, with no fetch of its own.
                    Log.Warn(Category, "apiable.keys_unavailable: {Error}", Log.ErrorName(error));
                    throw new KeysUnavailable(error);
                }
                if (MayFetch())
                {
                    await RefreshAsync().ConfigureAwait(false);
                }
            }
        }
        finally
        {
            _lock.Release();
        }
        if (_keys.TryGetValue(kid, out var key))
        {
            return key;
        }
        throw new UnknownKey(kid);
    }

    /// <summary><see cref="IssuerStatus.Offline"/> with no key, <see cref="IssuerStatus.Degraded"/> if the last fetch failed, else <see cref="IssuerStatus.Connected"/>.</summary>
    public IssuerStatus Status
    {
        get
        {
            if (_keys.Count == 0)
            {
                return IssuerStatus.Offline;
            }
            return _refreshFailed ? IssuerStatus.Degraded : IssuerStatus.Connected;
        }
    }

    private bool MayFetch() =>
        _fetchedAt is not { } at || _time.GetElapsedTime(at) >= _interval;

    private async Task RefreshAsync()
    {
        Dictionary<string, RSAParameters> keys;
        try
        {
            keys = LoadKeys(await FetchKeySetAsync().ConfigureAwait(false));
            if (keys.Count == 0)
            {
                // No usable key: a failed fetch. An empty set never replaces the keys in hand.
                throw new KeySetError("keys");
            }
        }
        catch (Exception error)
        {
            if (_fetchedAt is null)
            {
                // Cold: nothing to verify with. The failure is kept: the callers that waited for
                // this fetch get it, and so does every caller for the next 5 seconds.
                _coldError = error;
                _coldFailedAt = _time.GetTimestamp();
                Interlocked.Increment(ref _coldFailures);
                Log.Warn(Category, "apiable.keys_unavailable: {Error}", Log.ErrorName(error));
                throw new KeysUnavailable(error);
            }
            // Warm: the keys in hand go on verifying, and the issuer is not asked again for
            // another interval.
            _fetchedAt = _time.GetTimestamp();
            _refreshFailed = true;
            Log.Warn(Category, "apiable.keys_not_refreshed: {Error}", Log.ErrorName(error));
            return;
        }
        _keys = keys;
        _fetchedAt = _time.GetTimestamp();
        _refreshFailed = false;
        _coldError = null;
        var kids = keys.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray();
        Log.Info(Category, "apiable.keys_loaded kids={Kids}", JsonSerializer.Serialize(kids));
    }

    private async Task<JsonElement> FetchKeySetAsync()
    {
        var jwksUri = _jwksUri;
        if (jwksUri is null)
        {
            using var discovery = await GetJsonAsync($"{_issuer}/.well-known/openid-configuration").ConfigureAwait(false);
            var document = Field(discovery.RootElement, "issuer");
            if (document.ValueKind != JsonValueKind.String || document.GetString()!.TrimEnd('/') != _issuer)
            {
                throw new KeySetError("issuer");
            }
            var uri = Field(discovery.RootElement, "jwks_uri");
            // The key set comes over https only, or from a loopback host in local development.
            if (uri.ValueKind != JsonValueKind.String
                || !Uri.TryCreate(uri.GetString(), UriKind.Absolute, out var parsed) || !KeelieHttp.IsSecure(parsed))
            {
                throw new KeySetError("jwks_uri");
            }
            jwksUri = uri.GetString()!;
        }
        using var keySet = await GetJsonAsync(jwksUri).ConfigureAwait(false);
        var keys = Field(keySet.RootElement, "keys").Clone();
        _jwksUri = jwksUri;
        return keys;
    }

    private async Task<JsonDocument> GetJsonAsync(string url)
    {
        // One deadline for the whole document: the answer and its body. WaitAsync as well as the
        // token, so a handler that does not watch its token cannot hold the fetch longer.
        using var timeout = new CancellationTokenSource(FetchTimeout);
        var sending = _client.GetAsync(url, timeout.Token);
        HttpResponseMessage answer;
        try
        {
            answer = await sending.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // An answer that comes after all is not read.
            _ = sending.ContinueWith(late => late.Result.Dispose(), CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);
            throw;
        }
        using var response = answer;
        if (!response.IsSuccessStatusCode)
        {
            throw new KeySetError($"status {(int)response.StatusCode}");
        }
        var body = await response.Content.ReadAsByteArrayAsync(timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false);
        return JsonDocument.Parse(body);
    }

    private static JsonElement Field(JsonElement document, string name)
    {
        if (document.ValueKind != JsonValueKind.Object)
        {
            throw new KeySetError("document");
        }
        JsonElement? found = null;
        foreach (var property in document.EnumerateObject())
        {
            // A name given twice: the last value, as Python's parser keeps it.
            if (property.NameEquals(name))
            {
                found = property.Value;
            }
        }
        return found ?? throw new KeySetError(name);
    }

    private static Dictionary<string, RSAParameters> LoadKeys(JsonElement keySet)
    {
        if (keySet.ValueKind != JsonValueKind.Array)
        {
            throw new KeySetError("keys");
        }
        var keys = new Dictionary<string, RSAParameters>(StringComparer.Ordinal);
        foreach (var jwk in keySet.EnumerateArray())
        {
            // The issuer can publish an encryption key beside the signing key. Only an RSA key for
            // signing, with the one algorithm and a kid, verifies a token.
            if (jwk.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var members = Members(jwk);
            if (!members.TryGetValue("kid", out var kid) || kid.ValueKind != JsonValueKind.String
                || !IsString(members, "kty", "RSA")
                || !AbsentOr(members, "use", "sig")
                || !AbsentOr(members, "alg", Algorithm))
            {
                continue;
            }
            string? id = null;
            try
            {
                // An escaped lone surrogate in the kid throws here: that key is skipped.
                id = kid.GetString()!;
                // The public members only: a private member published by mistake is never loaded.
                var modulus = Base64Url(members, "n");
                var exponent = Base64Url(members, "e");
                if (BitLength(modulus) < MinModulusBits)
                {
                    throw new KeySetError("modulus");
                }
                var parameters = new RSAParameters { Modulus = modulus, Exponent = exponent };
                // Load it once here, so that a key that cannot load is skipped now, not at a token.
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(parameters);
                }
                keys[id] = parameters;
            }
            catch (Exception error) when (error is KeySetError or CryptographicException or FormatException or InvalidOperationException)
            {
                // A key the SDK cannot load is skipped. The rest of the set loads.
                Log.Warn(Category, "apiable.key_skipped kid={Kid}", id is null ? "null" : JsonSerializer.Serialize(id));
            }
        }
        return keys;
    }

    private static Dictionary<string, JsonElement> Members(JsonElement jwk)
    {
        var members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in jwk.EnumerateObject())
        {
            members[property.Name] = property.Value;
        }
        return members;
    }

    private static bool IsString(Dictionary<string, JsonElement> members, string name, string value) =>
        members.TryGetValue(name, out var member)
        && member.ValueKind == JsonValueKind.String
        && member.GetString() == value;

    private static bool AbsentOr(Dictionary<string, JsonElement> members, string name, string value) =>
        !members.TryGetValue(name, out var member)
        || member.ValueKind == JsonValueKind.Null
        || (member.ValueKind == JsonValueKind.String && member.GetString() == value);

    private static byte[] Base64Url(Dictionary<string, JsonElement> members, string name)
    {
        if (!members.TryGetValue(name, out var member) || member.ValueKind != JsonValueKind.String)
        {
            throw new KeySetError(name);
        }
        var text = member.GetString()!.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        if (text.Length % 4 == 1)
        {
            throw new KeySetError(name);
        }
        text = text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '=');
        var bytes = Convert.FromBase64String(text);
        if (bytes.Length == 0)
        {
            throw new KeySetError(name);
        }
        return bytes;
    }

    private static int BitLength(byte[] bigEndian)
    {
        var i = 0;
        while (i < bigEndian.Length && bigEndian[i] == 0)
        {
            i++;
        }
        if (i == bigEndian.Length)
        {
            return 0;
        }
        var top = bigEndian[i];
        var bits = 0;
        while (top != 0)
        {
            bits++;
            top >>= 1;
        }
        return ((bigEndian.Length - i - 1) * 8) + bits;
    }

    private sealed class KeySetError(string what) : Exception(what);
}
