using System.Diagnostics;
using System.Net;
using System.Text;
using Keelie.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Keelie.Tests;

public sealed class CatalogTests
{
    // A resource at the root: every path is under it, so the guards must let the catalog pass.
    private const string Resource = "https://api.example.test";
    private const string Document = "{\"specVersion\":\"1.0\",\"entries\":[]}";

    private sealed class CatalogKeelie : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];

        public string Body { get; set; } = Document;

        public object Answer { get; set; } = 200;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (Paths)
            {
                Paths.Add(request.RequestUri!.AbsolutePath);
            }
            // Yield, as a real fetch does, so that concurrent requests overlap.
            await Task.Delay(10, cancellationToken);
            if (Answer is Exception error)
            {
                throw error;
            }
            return new HttpResponseMessage((HttpStatusCode)(int)Answer) { Content = new StringContent(Body) };
        }
    }

    private static (AiCatalog Catalog, ProtectedResourceMetadata Metadata) Make(CatalogKeelie keelie, ManualClock clock)
    {
        var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer);
        var client = new HttpClient(keelie) { BaseAddress = new Uri(FakeKeelie.BaseUrl) };
        return (new AiCatalog(client, metadata, new AiCatalogOptions { TimeProvider = clock }), metadata);
    }

    [Fact]
    public void Making_it_tells_the_guards_that_its_paths_need_no_token()
    {
        var (_, metadata) = Make(new CatalogKeelie(), new ManualClock());

        Assert.True(metadata.ServesAiCatalog);
    }

    [Fact]
    public async Task Both_paths_serve_one_copy_with_their_media_types_and_keep_it_60_seconds()
    {
        var keelie = new CatalogKeelie();
        var clock = new ManualClock();
        var (catalog, _) = Make(keelie, clock);

        var ard = await catalog.AnswerAsync(AiCatalog.ArdPath);
        var ai = await catalog.AnswerAsync(AiCatalog.CatalogPath);

        Assert.Equal(200, ard!.Status);
        Assert.Equal("application/json", ard.Headers["Content-Type"]);
        Assert.Equal("application/ai-catalog+json", ai!.Headers["Content-Type"]);
        Assert.Equal("max-age=60", ai.Headers["Cache-Control"]);
        Assert.Equal(Document, Encoding.UTF8.GetString(ai.Body.Span));
        Assert.Equal([AiCatalog.KeeliePath], keelie.Paths);

        keelie.Body = "{\"specVersion\":\"1.0\",\"entries\":[{\"identifier\":\"x\"}]}";
        clock.Advance(59);
        var cached = await catalog.AnswerAsync(AiCatalog.ArdPath);
        clock.Advance(1);
        var fresh = await catalog.AnswerAsync(AiCatalog.ArdPath);

        Assert.Equal(2, keelie.Paths.Count);
        Assert.Equal(Document, Encoding.UTF8.GetString(cached!.Body.Span));
        // A plan published in keelie shows within 60 seconds.
        Assert.Equal(keelie.Body, Encoding.UTF8.GetString(fresh!.Body.Span));
        Assert.Null(await catalog.AnswerAsync("/other"));
    }

    [Theory]
    [InlineData("503")]
    [InlineData("network")]
    public async Task An_old_copy_is_never_served_when_keelie_fails(string failure)
    {
        var keelie = new CatalogKeelie();
        var clock = new ManualClock();
        var (catalog, _) = Make(keelie, clock);
        await catalog.AnswerAsync(AiCatalog.ArdPath);
        keelie.Answer = failure == "network" ? new HttpRequestException("down") : 503;

        clock.Advance(60);
        var answer = await catalog.AnswerAsync(AiCatalog.ArdPath);

        Assert.Equal(503, answer!.Status);
        Assert.True(answer.Body.IsEmpty);
        Assert.Equal("no-store", answer.Headers["Cache-Control"]);
        Assert.Equal("10", answer.Headers["Retry-After"]);
    }

    [Fact]
    public async Task After_a_failure_keelie_is_asked_again_after_10_seconds_not_on_each_request()
    {
        // The path is public. Traffic to it must not turn into one call to keelie for each request,
        // with the Provider's credential, while keelie fails.
        var keelie = new CatalogKeelie { Answer = 503 };
        var clock = new ManualClock();
        var (catalog, _) = Make(keelie, clock);

        var answers = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => catalog.AnswerAsync(AiCatalog.CatalogPath)));
        clock.Advance(9);
        var still = await catalog.AnswerAsync(AiCatalog.CatalogPath);
        keelie.Answer = 200;
        clock.Advance(1);
        var recovered = await catalog.AnswerAsync(AiCatalog.CatalogPath);

        Assert.All(answers, answer => Assert.Equal(503, answer!.Status));
        Assert.Equal(503, still!.Status);
        Assert.Equal(200, recovered!.Status);
        Assert.Equal(2, keelie.Paths.Count);
    }

    [Fact]
    public async Task One_fetch_serves_many_requests_at_once()
    {
        var keelie = new CatalogKeelie();
        var (catalog, _) = Make(keelie, new ManualClock());

        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => catalog.AnswerAsync(AiCatalog.ArdPath)));

        Assert.Single(keelie.Paths);
    }

    [Fact]
    public async Task Any_client_failure_is_a_503_with_the_same_back_off()
    {
        var keelie = new CatalogKeelie { Answer = new InvalidOperationException("no credential") };
        var (catalog, _) = Make(keelie, new ManualClock());

        var answers = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => catalog.AnswerAsync(AiCatalog.ArdPath)));

        Assert.All(answers, answer => Assert.Equal(503, answer!.Status));
        Assert.Single(keelie.Paths);
    }

    public static TheoryData<string, string, string> GuardsAndPaths()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var guard in new[] { "rest", "mcp" })
        {
            data.Add(guard, AiCatalog.ArdPath, "application/json");
            data.Add(guard, AiCatalog.CatalogPath, "application/ai-catalog+json");
        }
        return data;
    }

    private static Task<TestApp> ServeAsync(string guard, CatalogKeelie keelie, bool withCatalog = true) =>
        TestApp.StartAsync(app =>
        {
            var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer);
            var client = new HttpClient(keelie) { BaseAddress = new Uri(FakeKeelie.BaseUrl) };
            // Never asked: the catalog needs no token. Its audience is the resource, as a guard needs.
            var verifier = new TokenVerifier(Values.Issuer, Resource, Values.OrgId);
            if (withCatalog)
            {
                app.UseKeelieAiCatalog(new AiCatalog(client, metadata));
            }
            if (guard == "rest")
            {
                app.UseKeelieTokenGuard(verifier, metadata);
            }
            else
            {
                app.UseKeelieMcpGuard(verifier, metadata, new Dictionary<string, string>(), new UsageReporter(client));
            }
            app.Run(context =>
            {
                context.Response.StatusCode = 204;
                return Task.CompletedTask;
            });
        });

    [Theory]
    [MemberData(nameof(GuardsAndPaths))]
    public async Task The_catalog_is_keelies_document_with_no_token(string guard, string path, string mediaType)
    {
        var keelie = new CatalogKeelie();
        await using var app = await ServeAsync(guard, keelie);

        using var response = await app.SendAsync(HttpMethod.Get, path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(mediaType, response.Content.Headers.ContentType!.ToString());
        Assert.Equal(Document, await response.Content.ReadAsStringAsync());
        Assert.Equal("max-age=60", response.Headers.CacheControl!.ToString());
        Assert.Equal([AiCatalog.KeeliePath], keelie.Paths);
    }

    [Theory]
    [InlineData(AiCatalog.ArdPath)]
    [InlineData(AiCatalog.CatalogPath)]
    public async Task Head_answers_the_length_and_no_body(string path)
    {
        await using var app = await ServeAsync("rest", new CatalogKeelie());

        using var response = await app.SendAsync(HttpMethod.Head, path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(Document.Length, response.Content.Headers.ContentLength);
    }

    [Theory]
    [InlineData("POST", AiCatalog.ArdPath)]
    [InlineData("PUT", AiCatalog.CatalogPath)]
    [InlineData("DELETE", AiCatalog.CatalogPath)]
    public async Task Another_method_on_the_catalog_path_needs_a_token(string method, string path)
    {
        await using var app = await ServeAsync("rest", new CatalogKeelie());

        using var response = await app.SendAsync(new HttpMethod(method), path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(AiCatalog.ArdPath)]
    [InlineData(AiCatalog.CatalogPath)]
    public async Task A_guard_with_no_catalog_guards_the_catalog_path(string path)
    {
        await using var app = await ServeAsync("rest", new CatalogKeelie(), withCatalog: false);

        using var response = await app.SendAsync(HttpMethod.Get, path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

public sealed class SdkCredentialTests
{
    private sealed class Endpoints : HttpMessageHandler
    {
        public List<(string Url, string? Auth, string Body)> Calls { get; } = [];

        public int Minted;

        public bool Refuse { get; set; }

        public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;

        /// <summary>While true, the token endpoint never answers, and does not watch the cancellation token either.</summary>
        public volatile bool Stall;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (Calls)
            {
                Calls.Add((request.RequestUri!.ToString(), request.Headers.Authorization?.ToString(), body));
            }
            await Task.Delay(10, cancellationToken);
            if (request.RequestUri!.ToString() == "https://issuer.example.test/token")
            {
                if (Stall)
                {
                    await new TaskCompletionSource<bool>().Task;
                }
                if (TokenStatus != HttpStatusCode.OK)
                {
                    return new HttpResponseMessage(TokenStatus);
                }
                var minted = Interlocked.Increment(ref Minted);
                return FakeIssuer.Json(new { access_token = $"token-{minted}", expires_in = 300 });
            }
            if (Refuse)
            {
                Refuse = false;
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }
            return FakeIssuer.Json(new { ok = true });
        }
    }

    private static HttpClient Client(Endpoints endpoints, string secret = "s3cret", TimeSpan? timeout = null) =>
        new(new SdkCredential(new SdkCredentialOptions
        {
            KeelieUrl = "https://keelie.example.test/",
            TokenUrl = "https://issuer.example.test/token",
            ClientId = "sdk",
            ClientSecret = secret,
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
        }) { InnerHandler = endpoints })
        {
            BaseAddress = new Uri("https://keelie.example.test/"),
        };

    [Fact]
    public async Task It_mints_a_token_once_sends_it_and_mints_again_on_a_401()
    {
        var endpoints = new Endpoints();
        using var keelie = Client(endpoints);

        await Task.WhenAll(keelie.GetAsync(new Uri("https://keelie.example.test/ai-catalog")), keelie.GetAsync(new Uri("https://keelie.example.test/ai-catalog")));

        Assert.Equal(1, endpoints.Minted);
        Assert.Equal("grant_type=client_credentials&client_id=sdk&client_secret=s3cret", endpoints.Calls[0].Body);
        Assert.Equal(
            [("https://keelie.example.test/ai-catalog", "Bearer token-1"), ("https://keelie.example.test/ai-catalog", "Bearer token-1")],
            endpoints.Calls.Skip(1).Select(c => (c.Url, c.Auth)));

        endpoints.Refuse = true;
        using var response = await keelie.PostAsync(new Uri("https://keelie.example.test/usage-events:report"), new StringContent("{}"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, endpoints.Minted);
        Assert.Equal("Bearer token-2", endpoints.Calls[^1].Auth);
        Assert.Equal("{}", endpoints.Calls[^1].Body);
    }

    [Fact]
    public async Task It_fails_when_the_token_endpoint_refuses()
    {
        var endpoints = new Endpoints { TokenStatus = HttpStatusCode.Unauthorized };
        using var keelie = Client(endpoints, "wrong");

        await Assert.ThrowsAsync<HttpRequestException>(() => keelie.GetAsync(new Uri("https://keelie.example.test/ai-catalog")));
    }

    [Fact]
    public async Task A_token_endpoint_that_never_answers_fails_that_attempt_and_the_next_call_mints_again()
    {
        // The client's own timeout is 100 seconds: only the mint's timeout can end the first calls.
        var endpoints = new Endpoints { Stall = true };
        using var keelie = Client(endpoints, timeout: TimeSpan.FromMilliseconds(300));
        var catalog = new Uri("https://keelie.example.test/ai-catalog");
        var clock = Stopwatch.StartNew();

        var first = keelie.GetAsync(catalog);
        var waiter = keelie.GetAsync(catalog); // shares the stalled mint
        await Assert.ThrowsAsync<TimeoutException>(() => first);
        await Assert.ThrowsAsync<TimeoutException>(() => waiter);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"took {clock.Elapsed}");

        // A caller can also stop waiting on its own. The callers above can time out a little
        // before the stalled mint itself ends, and a call made before then would join that mint
        // and get its timeout, so wait for it to end first.
        await Task.Delay(1000);
        using (var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(50)))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => keelie.GetAsync(catalog, stop.Token));
        }

        endpoints.Stall = false;
        await Task.Delay(1000); // the third mint, still stalled, times out first
        using var response = await keelie.GetAsync(catalog);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, endpoints.Minted);
        Assert.Equal("Bearer token-1", endpoints.Calls[^1].Auth);
    }

    [Fact]
    public async Task A_redirect_from_the_token_endpoint_is_not_followed_and_the_secret_is_sent_once()
    {
        var elsewhere = new List<string>();
        await using var other = await TestApp.StartAsync(app => app.MapPost("/token", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            var body = await reader.ReadToEndAsync();
            lock (elsewhere)
            {
                elsewhere.Add(body);
            }
            return Results.Json(new { access_token = "stolen", expires_in = 300 });
        }));
        var issuerCalls = 0;
        // Another host: localhost, where the issuer is 127.0.0.1.
        var target = $"http://localhost:{other.Url.Port}/token";
        await using var issuer = await TestApp.StartAsync(app => app.MapPost("/token", () =>
        {
            Interlocked.Increment(ref issuerCalls);
            return Results.Redirect(target, permanent: false, preserveMethod: true);
        }));
        using var keelie = SdkCredential.CreateClient(new SdkCredentialOptions
        {
            KeelieUrl = other.Url.ToString(),
            TokenUrl = new Uri(issuer.Url, "/token").ToString(),
            ClientId = "sdk",
            ClientSecret = "s3cret",
        });

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => keelie.GetAsync(new Uri(other.Url, "/ai-catalog")));

        Assert.Equal(HttpStatusCode.TemporaryRedirect, error.StatusCode);
        Assert.Equal(1, issuerCalls);
        Assert.Empty(elsewhere);
    }

    [Fact]
    public async Task It_refuses_a_handler_that_follows_redirects()
    {
        var options = new SdkCredentialOptions
        {
            KeelieUrl = "https://keelie.example.test/",
            TokenUrl = "https://issuer.example.test/token",
            ClientId = "sdk",
            ClientSecret = "s3cret",
        };
        HttpMessageHandler[] following =
        [
            new HttpClientHandler(),
            new SocketsHttpHandler(),
            new Passthrough { InnerHandler = new SocketsHttpHandler() },
        ];
        foreach (var inner in following)
        {
            using var keelie = new HttpClient(new SdkCredential(options) { InnerHandler = inner });
            await Assert.ThrowsAsync<InvalidOperationException>(() => keelie.GetAsync(new Uri("https://keelie.example.test/ai-catalog")));
        }
        Assert.False(SdkCredential.FollowsRedirects(new Passthrough { InnerHandler = new SocketsHttpHandler { AllowAutoRedirect = false } }));
        Assert.False(SdkCredential.FollowsRedirects(new Endpoints()));
    }

    private sealed class Passthrough : DelegatingHandler
    {
    }

    [Fact]
    public void Create_client_sets_the_address_and_the_timeout()
    {
        using var client = SdkCredential.CreateClient(new SdkCredentialOptions
        {
            KeelieUrl = "https://keelie.example.test",
            TokenUrl = "https://issuer.example.test/token",
            ClientId = "sdk",
            ClientSecret = "s3cret",
        });

        Assert.Equal(new Uri("https://keelie.example.test"), client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(10), client.Timeout);
    }
}
