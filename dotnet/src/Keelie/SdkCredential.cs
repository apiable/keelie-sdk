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

    /// <summary>How long a call to keelie, with the token it may mint first, may take. 10 seconds.</summary>
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
/// </remarks>
public sealed class SdkCredential : DelegatingHandler
{
    private readonly Uri _tokenUrl;
    private readonly Dictionary<string, string> _form;
    private readonly TimeProvider _time;
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
        _tokenUrl = new Uri(options.TokenUrl, UriKind.Absolute);
        _form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = options.ClientId,
            ["client_secret"] = options.ClientSecret,
        };
        _time = time;
    }

    /// <summary>
    /// A client for keelie: its address as the base address, a token of your SDK credential on each
    /// request, and the timeout in <paramref name="options"/>. Give it to <see cref="UsageReporter"/>
    /// and <see cref="AiCatalog"/>. Make one for the process.
    /// </summary>
    public static HttpClient CreateClient(SdkCredentialOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var handler = new SdkCredential(options) { InnerHandler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) } };
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

    /// <summary>Mint a token if none is fresh, or if <paramref name="force"/>. One mint at a time, for every caller.</summary>
    private async Task FreshAsync(bool force, CancellationToken cancellationToken)
    {
        Task? minting;
        lock (_gate)
        {
            var expired = !_minted || _time.GetTimestamp() >= _expiresAt;
            if (_minting is null && (force || expired))
            {
                _minting = MintAsync();
            }
            minting = _minting;
        }
        if (minting is not null)
        {
            await minting.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task MintAsync()
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _tokenUrl)
            {
                Content = new FormUrlEncodedContent(_form),
            };
            using var response = await base.SendAsync(request, CancellationToken.None).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"the token endpoint answered {(int)response.StatusCode}", null, response.StatusCode);
            }
            var body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
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
        finally
        {
            lock (_gate)
            {
                _minting = null;
            }
        }
    }
}
