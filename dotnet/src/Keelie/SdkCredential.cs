using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Keelie;

/// <summary>Options of <see cref="SdkCredential"/>. Read each value from the environment, never from source code.</summary>
public sealed class SdkCredentialOptions
{
    /// <summary>The address of keelie: <c>KEELIE_URL</c>.</summary>
    public required string KeelieUrl { get; init; }

    /// <summary>The token endpoint of keelie's issuer: <c>KEELIE_TOKEN_URL</c>.</summary>
    public required string TokenUrl { get; init; }

    /// <summary><c>sdk_credential.client_id</c> from the signup answer.</summary>
    public required string ClientId { get; init; }

    /// <summary><c>sdk_credential.client_secret</c> from the signup answer.</summary>
    public required string ClientSecret { get; init; }

    /// <summary>
    /// How long a call to keelie, with the token it may mint first, may take. 10 seconds. A mint
    /// gets the same time on its own: one that takes longer fails, and the next call mints again.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
}

/// <summary>
/// Talk to keelie with your SDK credential.
/// </summary>
/// <remarks>
/// The usage reporter and the AI Catalog call keelie's API. Each call carries a token of the
/// <c>sdk_credential</c> from your signup: it may report usage and read your products, and nothing
/// else. This handler mints that token at your issuer with the client credentials grant, keeps it
/// until shortly before it expires, and mints again on a <c>401</c>, then sends the request once
/// more.
/// <para>
/// The SDK holds no secret of its own. Never give it your admin credential.
/// </para>
/// <para>
/// The handler under it must not follow redirects: a <c>307</c> or <c>308</c> would send the client
/// secret again, to the new address. <see cref="CreateClient"/> makes one that does not. If you
/// build your own client, set <c>AllowAutoRedirect = false</c> on its <see cref="SocketsHttpHandler"/>
/// or <see cref="HttpClientHandler"/>, the primary handler of a named client from
/// <c>IHttpClientFactory</c> too. This handler refuses to send through one that follows redirects.
/// </para>
/// </remarks>
public sealed class SdkCredential : DelegatingHandler
{
    private readonly Uri _tokenUrl;
    private readonly Dictionary<string, string> _form;
    private readonly TimeProvider _time;
    private readonly TimeSpan _timeout;
    private readonly CancellationTokenSource _disposed = new();
    private readonly object _gate = new();
    private string _token = string.Empty;
    private long _expiresAt;
    private bool _minted;
    private Task? _minting;

    /// <summary>A handler that adds a token of the credential in <paramref name="options"/> to each request.</summary>
    public SdkCredential(SdkCredentialOptions options)
        : this(options, TimeProvider.System)
    {
    }

    internal SdkCredential(SdkCredentialOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.Timeout, TimeSpan.Zero, nameof(options));
        _tokenUrl = new Uri(options.TokenUrl, UriKind.Absolute);
        _form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = options.ClientId,
            ["client_secret"] = options.ClientSecret,
        };
        _time = time;
        _timeout = options.Timeout;
    }

    /// <summary>
    /// A client for keelie: its address as the base address, a token of your SDK credential on each
    /// request, and the timeout in <paramref name="options"/>. Give it to <see cref="UsageReporter"/>
    /// and <see cref="AiCatalog"/>. Make one for the process.
    /// </summary>
    public static HttpClient CreateClient(SdkCredentialOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        // No redirect is followed: a 307 or 308 from the token endpoint would send the secret on.
        var inner = new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
        var handler = new SdkCredential(options) { InnerHandler = inner };
        return new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = new Uri(options.KeelieUrl, UriKind.Absolute),
            Timeout = options.Timeout,
        };
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (FollowsRedirects(InnerHandler))
        {
            throw new InvalidOperationException(
                "the handler under SdkCredential follows redirects, which would send the client secret to another address: set AllowAutoRedirect = false on it");
        }
        await FreshAsync(force: false, cancellationToken).ConfigureAwait(false);
        if (request.Content is not null)
        {
            // Kept, so that the request can be sent a second time after a 401.
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }
        response.Dispose();
        await FreshAsync(force: true, cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private string Token
    {
        get
        {
            lock (_gate)
            {
                return _token;
            }
        }
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // A mint in flight stops, and its waiters with it. Not disposed: it holds no timer, and
            // a late call still reads its token.
            _disposed.Cancel();
        }
        base.Dispose(disposing);
    }

    /// <summary>
    /// True when a handler in the chain under this one follows redirects. Only the two handlers of
    /// .NET are known; a handler of another kind is taken at its word.
    /// </summary>
    internal static bool FollowsRedirects(HttpMessageHandler? handler)
    {
        for (var current = handler; current is not null; current = (current as DelegatingHandler)?.InnerHandler)
        {
            if (current is SocketsHttpHandler { AllowAutoRedirect: true } or HttpClientHandler { AllowAutoRedirect: true })
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Mint a token if none is fresh, or if <paramref name="force"/>. One mint at a time, for every
    /// caller. Each caller waits at most the timeout and can stop waiting with its own token; the
    /// mint itself ends within the timeout, so a stalled token endpoint fails one attempt and the
    /// next call mints again.
    /// </summary>
    private async Task FreshAsync(bool force, CancellationToken cancellationToken)
    {
        Task? minting;
        lock (_gate)
        {
            var expired = !_minted || _time.GetTimestamp() >= _expiresAt;
            if (_minting is null && (force || expired))
            {
                // On the thread pool, so that the mint never runs, or ends, inside this lock.
                _minting = Task.Run(MintAsync);
            }
            minting = _minting;
        }
        if (minting is null)
        {
            return;
        }
        try
        {
            await minting.WaitAsync(_timeout, _time, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException) when (!minting.IsCompleted)
        {
            throw new TimeoutException($"the token endpoint did not answer in {_timeout.TotalSeconds:0.###} s");
        }
    }

    private async Task MintAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(_timeout, _time);
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, _disposed.Token);
            try
            {
                await MintOnceAsync(stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                throw new TimeoutException($"the token endpoint did not answer in {_timeout.TotalSeconds:0.###} s");
            }
        }
        finally
        {
            lock (_gate)
            {
                _minting = null;
            }
        }
    }

    private async Task MintOnceAsync(CancellationToken stop)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, _tokenUrl)
        {
            Content = new FormUrlEncodedContent(_form),
        };
        // WaitAsync as well as the token: the mint ends on time even under a handler that does not
        // watch its token.
        var sending = base.SendAsync(request, stop);
        HttpResponseMessage response;
        try
        {
            response = await sending.WaitAsync(stop).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // An answer that comes after all is not read.
            _ = sending.ContinueWith(late => late.Result.Dispose(), CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);
            throw;
        }
        using (response)
        {
            if ((int)response.StatusCode is >= 300 and < 400)
            {
                // Never followed: the secret goes to the token endpoint and nowhere else.
                throw new HttpRequestException($"the token endpoint answered {(int)response.StatusCode}, a redirect, which the SDK does not follow", null, response.StatusCode);
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"the token endpoint answered {(int)response.StatusCode}", null, response.StatusCode);
            }
            var body = await response.Content.ReadAsByteArrayAsync(stop).WaitAsync(stop).ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("access_token", out var accessToken) || accessToken.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("expires_in", out var expiresIn) || !expiresIn.TryGetDouble(out var lifetime))
            {
                throw new HttpRequestException("the token endpoint answered without a token");
            }
            // Mint again before the token expires.
            var keep = TimeSpan.FromSeconds(Math.Max(lifetime - 30, lifetime / 2));
            lock (_gate)
            {
                _token = accessToken.GetString()!;
                _expiresAt = _time.GetTimestamp() + (long)(keep.TotalSeconds * _time.TimestampFrequency);
                _minted = true;
            }
        }
    }
}
