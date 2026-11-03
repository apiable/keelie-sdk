// The issuer, the tokens, keelie and a running ASP.NET Core app the tests share. No network: every
// fake answers in the process, and the apps listen on the loopback address only.

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keelie.Tests;

internal static class Values
{
    public const string Issuer = "https://issuer.example.test/realms/test";
    // The resource of the REST API under test, and so the aud of its tokens.
    public const string Audience = "https://api.example.test/api";
    public static readonly Guid OrgId = Guid.Parse("01890000-0000-7000-8000-000000000001");
}

/// <summary>An RSA key and its public JWK.</summary>
internal sealed class TestKey
{
    public TestKey(string kid, int bits = 2048)
    {
        Kid = kid;
        Rsa = RSA.Create(bits);
    }

    public string Kid { get; }

    public RSA Rsa { get; }

    public Dictionary<string, object?> Jwk(Dictionary<string, object?>? extra = null)
    {
        var parameters = Rsa.ExportParameters(false);
        var jwk = new Dictionary<string, object?>
        {
            ["kty"] = "RSA",
            ["n"] = Tokens.Base64Url(parameters.Modulus!),
            ["e"] = Tokens.Base64Url(parameters.Exponent!),
            ["kid"] = Kid,
            ["use"] = "sig",
            ["alg"] = "RS256",
        };
        foreach (var (name, value) in extra ?? [])
        {
            if (ReferenceEquals(value, Tokens.Omit))
            {
                jwk.Remove(name);
            }
            else
            {
                jwk[name] = value;
            }
        }
        return jwk;
    }
}

/// <summary>Tokens signed in the test, with the claims of the token rules.</summary>
internal static class Tokens
{
    /// <summary>A claim given this value is left out.</summary>
    public static readonly object Omit = new();

    public static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    public static Dictionary<string, object?> Claims(Dictionary<string, object?>? overrides = null)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = Values.Issuer,
            ["aud"] = Values.Audience,
            ["exp"] = Now + 300,
            ["iat"] = Now,
            ["typ"] = "Bearer",
            ["azp"] = "client-1",
            ["sub"] = "service-account-user",
            ["org_id"] = Values.OrgId.ToString(),
            ["scope"] = "orders:read orders:write",
            ["jti"] = "jti-1",
        };
        foreach (var (name, value) in overrides ?? [])
        {
            if (ReferenceEquals(value, Omit))
            {
                claims.Remove(name);
            }
            else
            {
                claims[name] = value;
            }
        }
        return claims;
    }

    public static string Sign(TestKey key, Dictionary<string, object?>? overrides = null, string? kid = null, Dictionary<string, object?>? header = null)
    {
        var head = new Dictionary<string, object?> { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = kid ?? key.Kid };
        foreach (var (name, value) in header ?? [])
        {
            if (ReferenceEquals(value, Omit))
            {
                head.Remove(name);
            }
            else
            {
                head[name] = value;
            }
        }
        var input = $"{Part(head)}.{Part(Claims(overrides))}";
        var signature = key.Rsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{input}.{Base64Url(signature)}";
    }

    /// <summary>A token whose payload is <paramref name="payload"/> as it is, signed with <paramref name="key"/>.</summary>
    public static string SignPayload(TestKey key, object payload)
    {
        var input = $"{Part(new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = key.Kid })}.{Part(payload)}";
        var signature = key.Rsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{input}.{Base64Url(signature)}";
    }

    /// <summary>A token with any header and a made-up signature, for the checks that run before a key is fetched.</summary>
    public static string Unsigned(Dictionary<string, object?> header, Dictionary<string, object?>? overrides = null) =>
        $"{Part(header)}.{Part(Claims(overrides))}.{Base64Url("sig"u8.ToArray())}";

    /// <summary>A token signed with a shared secret, as an attacker would make one.</summary>
    public static string Hs256(string kid)
    {
        var input = $"{Part(new Dictionary<string, object?> { ["alg"] = "HS256", ["typ"] = "JWT", ["kid"] = kid })}.{Part(Claims())}";
        var signature = HMACSHA256.HashData(Encoding.ASCII.GetBytes(new string('x', 32)), Encoding.ASCII.GetBytes(input));
        return $"{input}.{Base64Url(signature)}";
    }

    public static string Part(object value) => Base64Url(JsonSerializer.SerializeToUtf8Bytes(value));

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// The issuer's discovery document and key set, served without a network. <see cref="Says"/> is the
/// issuer its discovery document names: the realm itself, unless a test makes it lie.
/// </summary>
internal sealed class FakeIssuer : HttpMessageHandler
{
    public FakeIssuer(string url = Values.Issuer, string? says = null)
    {
        Url = url;
        Says = says ?? url;
        JwksUri = $"{url}/protocol/openid-connect/certs";
    }

    public string Url { get; }

    public string Says { get; set; }

    public string JwksUri { get; }

    public List<object> Keys { get; set; } = [];

    public int JwksFetches;

    public volatile bool Down;

    public ConcurrentQueue<string> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        Requests.Enqueue(url);
        // Yield, as a real fetch does, so that concurrent callers overlap.
        await Task.Delay(10, cancellationToken);
        if (Down)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }
        if (url == $"{Url}/.well-known/openid-configuration")
        {
            return Json(new { issuer = Says, jwks_uri = JwksUri });
        }
        if (url == JwksUri)
        {
            Interlocked.Increment(ref JwksFetches);
            return Json(new { keys = Keys });
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    public SigningKeys SigningKeys(TimeProvider? clock = null) =>
        new(Url, new SigningKeysOptions { HttpClient = new HttpClient(this), TimeProvider = clock });

    public TokenVerifier Verifier(TimeProvider? clock = null, string audience = Values.Audience) =>
        new(Url, audience, Values.OrgId, new TokenVerifierOptions { Keys = SigningKeys(clock) });

    public static HttpResponseMessage Json(object value) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value)) };
}

/// <summary>The issuer of most tests: one signing key, and keys that must verify nothing beside it.</summary>
internal static class StandardIssuer
{
    public static (FakeIssuer Issuer, TestKey Key) Make()
    {
        var key = new TestKey("sig-1");
        var other = new TestKey("enc-1");
        var issuer = new FakeIssuer();
        var signingJwk = key.Jwk();
        issuer.Keys =
        [
            // Keys that must verify nothing: one for encryption, one for another algorithm, and
            // one that cannot load. The rest of the set still loads.
            other.Jwk(new() { ["use"] = "enc", ["alg"] = "RSA-OAEP" }),
            new TestKeyAlias(key, "enc-rs256").Jwk(new() { ["use"] = "enc" }),
            new TestKeyAlias(key, "rs512").Jwk(new() { ["alg"] = "RS512" }),
            new TestKeyAlias(key, "broken").Jwk(new() { ["n"] = "!" }),
            signingJwk,
            // A key with no use and no alg is a signing key.
            new TestKeyAlias(key, "bare").Jwk(new() { ["use"] = Tokens.Omit, ["alg"] = Tokens.Omit }),
        ];
        return (issuer, key);
    }
}

/// <summary>The same RSA key under another kid.</summary>
internal sealed class TestKeyAlias(TestKey key, string kid)
{
    public Dictionary<string, object?> Jwk(Dictionary<string, object?>? extra = null)
    {
        var jwk = key.Jwk(extra);
        jwk["kid"] = kid;
        return jwk;
    }
}

/// <summary>A clock the test moves by hand. Only the monotonic part moves; the wall clock is real.</summary>
internal sealed class ManualClock : TimeProvider
{
    private long _ticks = TimeSpan.FromSeconds(1000).Ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => Interlocked.Read(ref _ticks);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);

    public void Advance(double seconds) => Advance(TimeSpan.FromSeconds(seconds));
}

/// <summary>A request keelie got, with its body read.</summary>
internal sealed record Sent(string Method, string Uri, Dictionary<string, string> Headers, string Body)
{
    public List<Dictionary<string, string>> Events =>
        JsonSerializer.Deserialize<Dictionary<string, List<Dictionary<string, string>>>>(Body)!["events"];
}

/// <summary>keelie's API, served without a network.</summary>
internal sealed class FakeKeelie : HttpMessageHandler
{
    public const string BaseUrl = "https://keelie.example.test";

    public ConcurrentQueue<Sent> Requests { get; } = new();

    /// <summary>The next answers: a status code, or an exception to throw.</summary>
    public ConcurrentQueue<object> Answers { get; } = new();

    public string? ProblemType { get; set; }

    /// <summary>While set and not completed, every request waits.</summary>
    public TaskCompletionSource? Hold { get; set; }

    public Func<HttpRequestMessage, HttpResponseMessage>? Respond { get; set; }

    public HttpClient Client() => new(this, disposeHandler: false) { BaseAddress = new Uri(BaseUrl) };

    public List<List<Dictionary<string, string>>> Batches() => Requests.Select(r => r.Events).ToList();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
            .ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Enqueue(new Sent(request.Method.Method, request.RequestUri!.ToString(), headers, body));
        if (Hold is { } hold)
        {
            await hold.Task.WaitAsync(cancellationToken);
        }
        if (Respond is { } respond)
        {
            return respond(request);
        }
        var answer = Answers.TryDequeue(out var next) ? next : 200;
        if (answer is Exception error)
        {
            throw error;
        }
        var status = (int)answer;
        if (status == 200)
        {
            return FakeIssuer.Json(new { accepted = 1, duplicates = 0 });
        }
        object problem = ProblemType is null ? new { } : new { type = ProblemType, status };
        return new HttpResponseMessage((HttpStatusCode)status) { Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(problem)) };
    }
}

/// <summary>An ASP.NET Core app on a free loopback port.</summary>
internal sealed class TestApp : IAsyncDisposable
{
    private readonly WebApplication _app;

    private TestApp(WebApplication app, Uri url)
    {
        _app = app;
        Url = url;
        Http = new HttpClient { BaseAddress = url };
    }

    public Uri Url { get; }

    public HttpClient Http { get; }

    public static async Task<TestApp> StartAsync(Action<WebApplication> configure, Action<IServiceCollection>? services = null)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrel().UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        services?.Invoke(builder.Services);
        var app = builder.Build();
        configure(app);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        return new TestApp(app, new Uri(address));
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? authorization = null, string? body = null, string? contentType = "application/json")
    {
        var request = new HttpRequestMessage(method, path);
        if (authorization is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8);
            request.Content.Headers.ContentType = contentType is null ? null : new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        }
        return await Http.SendAsync(request);
    }

    /// <summary>
    /// The status of a request whose target goes out byte for byte, as the client wrote it. An
    /// HttpClient would resolve dot segments and escapes before it sends.
    /// </summary>
    public async Task<int> RawStatusAsync(string target, string method = "GET", string? authorization = null)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(Url.Host, Url.Port);
        await using var stream = tcp.GetStream();
        var request = new StringBuilder($"{method} {target} HTTP/1.1\r\nHost: {Url.Host}:{Url.Port}\r\nConnection: close\r\n");
        if (authorization is not null)
        {
            request.Append($"Authorization: {authorization}\r\n");
        }
        request.Append("Content-Length: 0\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()));
        using var reader = new StreamReader(stream, Encoding.ASCII);
        var status = await reader.ReadLineAsync() ?? throw new IOException("no answer");
        return int.Parse(status.Split(' ')[1], System.Globalization.CultureInfo.InvariantCulture);
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>Every log line the SDK writes during the tests, kept in memory.</summary>
internal static class LogCapture
{
    private static readonly ConcurrentQueue<(LogLevel Level, string Category, string Message)> Lines = new();

    [ModuleInitializer]
    internal static void Install() => KeelieLogging.LoggerFactory = new Factory();

    public static void Clear() => Lines.Clear();

    public static string Text => string.Join("\n", Lines.Select(line => line.Message));

    public static IReadOnlyList<(LogLevel Level, string Category, string Message)> All => Lines.ToArray();

    private sealed class Factory : ILoggerFactory
    {
        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName) => new Logger(categoryName);

        public void Dispose()
        {
        }
    }

    private sealed class Logger(string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue((logLevel, category, formatter(state, exception)));
    }
}

/// <summary>The tests that read the log run alone, so that no other test writes to it meanwhile.</summary>
[CollectionDefinition("logs", DisableParallelization = true)]
public sealed class LogsCollection;

internal static class Wait
{
    public static async Task UntilAsync(Func<bool> condition, int milliseconds = 3000)
    {
        var end = DateTime.UtcNow.AddMilliseconds(milliseconds);
        while (!condition())
        {
            if (DateTime.UtcNow > end)
            {
                throw new TimeoutException("the condition never became true");
            }
            await Task.Delay(10);
        }
    }
}
