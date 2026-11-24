using System.Net;
using System.Text.Json;
using Keelie.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Keelie.Tests;

public sealed class TokenGuardTests : IAsyncLifetime
{
    private const string Resource = "https://api.example.test/v1";
    private const string MetadataUrl = "https://api.example.test/.well-known/oauth-protected-resource/v1";

    private readonly FakeIssuer _issuer;
    private readonly TestKey _key;
    private readonly ProtectedResourceMetadata _metadata = new(Resource, Values.Issuer);
    private TestApp _app = null!;
    private int _adminRuns;

    public TokenGuardTests() => (_issuer, _key) = StandardIssuer.Make();

    public async ValueTask InitializeAsync()
    {
        var verifier = _issuer.Verifier(audience: Resource);
        var scopes = new ScopeMap(new Dictionary<string, string>
        {
            ["GET /v1/orders/{orderId}"] = "orders:read",
            ["POST /v1/orders"] = "orders:write",
            ["GET /v1/items/{itemId}"] = "items:read",
        });
        _app = await TestApp.StartAsync(app =>
        {
            app.UseKeelieTokenGuard(verifier, _metadata);
            app.MapGet("/health", () => Results.Ok(new { ok = true }));
            app.MapGet("/v1/orders/{orderId}", (string orderId, HttpContext http) =>
                Results.Ok(new { orderId, azp = http.GetKeelieClaims()!.Azp })).RequireKeelieScope(scopes, _metadata);
            app.MapPost("/v1/orders", () => Results.StatusCode(201)).RequireKeelieScope(scopes, _metadata);
            app.MapGet("/v1/unmapped", () => Results.Ok()).RequireKeelieScope(scopes, _metadata);
            app.MapGroup("/v1").MapGet("/items/{itemId}", () => Results.Ok(new { item = true })).RequireKeelieScope(scopes, _metadata);
            app.MapGet("/v1/no-scope-check", (HttpContext http) => Results.Ok(new { claims = http.GetKeelieClaims() is not null }));
            app.MapMethods("/v1/orders/{orderId}", ["OPTIONS"], () => Results.NoContent());
            // An endpoint for every method, OPTIONS included.
            app.Map("/v1/admin", () =>
            {
                Interlocked.Increment(ref _adminRuns);
                return Results.Ok();
            });
        });
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    private string Token(Dictionary<string, object?>? overrides = null)
    {
        var claims = new Dictionary<string, object?> { ["aud"] = Resource };
        foreach (var (name, value) in overrides ?? [])
        {
            claims[name] = value;
        }
        return "Bearer " + Tokens.Sign(_key, claims);
    }

    [Fact]
    public async Task It_serves_the_metadata_with_no_token()
    {
        using var get = await _app.SendAsync(HttpMethod.Get, "/.well-known/oauth-protected-resource/v1");
        using var head = await _app.SendAsync(HttpMethod.Head, "/.well-known/oauth-protected-resource/v1");

        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal("application/json", get.Content.Headers.ContentType!.ToString());
        Assert.Equal(_metadata.Document, await get.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal(_metadata.Document.Length, head.Content.Headers.ContentLength);
        Assert.Empty(await head.Content.ReadAsByteArrayAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer ")]
    [InlineData("Bearer")]
    [InlineData("bearer  ")]
    public async Task A_request_with_no_bearer_token_gets_401_and_the_challenge(string? authorization)
    {
        using var response = await _app.SendAsync(HttpMethod.Get, "/v1/orders/42", authorization);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task A_forged_host_does_not_move_the_challenge()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/orders/42");
        request.Headers.Host = "attacker.example.test";
        using var response = await _app.Http.SendAsync(request);

        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task A_bad_token_is_refused_the_same_way_for_every_reason()
    {
        foreach (var authorization in new[]
        {
            "Bearer nope",
            Token(new() { ["org_id"] = Guid.NewGuid().ToString() }),
            Token(new() { ["exp"] = Tokens.Now - 31 }),
            "Bearer " + Tokens.Sign(new TestKey("sig-1"), new() { ["aud"] = Resource }),
            Token(new() { ["aud"] = "https://api.example.test/v2" }),
        })
        {
            using var response = await _app.SendAsync(HttpMethod.Get, "/v1/orders/42", authorization);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        }
    }

    [Fact]
    public async Task It_gives_the_claims_to_an_endpoint_whose_scope_the_token_carries()
    {
        using var response = await _app.SendAsync(HttpMethod.Get, "/v1/orders/42", Token());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("{\"orderId\":\"42\",\"azp\":\"client-1\"}", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("POST", "/v1/orders", "orders:read")]
    [InlineData("GET", "/v1/unmapped", "orders:read orders:write")]
    [InlineData("GET", "/v1/items/7", "orders:read orders:write")]
    public async Task It_answers_403_to_an_endpoint_whose_scope_the_token_lacks_or_that_is_not_in_the_map(string method, string path, string scope)
    {
        using var response = await _app.SendAsync(new HttpMethod(method), path, Token(new() { ["scope"] = scope }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal($"Bearer error=\"insufficient_scope\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task It_reads_the_template_of_an_endpoint_in_a_route_group()
    {
        using var allowed = await _app.SendAsync(HttpMethod.Get, "/v1/items/7", Token(new() { ["scope"] = "items:read" }));

        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task An_endpoint_with_no_scope_check_is_authenticated()
    {
        using var refused = await _app.SendAsync(HttpMethod.Get, "/v1/no-scope-check");
        using var allowed = await _app.SendAsync(HttpMethod.Get, "/v1/no-scope-check", Token());

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal("{\"claims\":true}", await allowed.Content.ReadAsStringAsync());
    }

    private async Task<HttpResponseMessage> OptionsAsync(string path, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, path);
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }
        return await _app.Http.SendAsync(request);
    }

    [Fact]
    public async Task Paths_outside_the_resource_and_a_preflight_pass_untouched()
    {
        using var health = await _app.SendAsync(HttpMethod.Get, "/health");
        using var preflight = await OptionsAsync("/v1/orders/42", ("Origin", "https://app.example.test"), ("Access-Control-Request-Method", "GET"));

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, preflight.StatusCode);
    }

    [Fact]
    public async Task An_options_request_that_is_no_preflight_needs_a_token()
    {
        using var admin = await OptionsAsync("/v1/admin");
        using var orders = await OptionsAsync("/v1/orders/42", ("Origin", "https://app.example.test"));
        using var withToken = await OptionsAsync("/v1/admin", ("Authorization", Token()));

        Assert.Equal(HttpStatusCode.Unauthorized, admin.StatusCode);
        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", admin.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, orders.StatusCode);
        Assert.Equal(HttpStatusCode.OK, withToken.StatusCode);
        Assert.Equal(1, _adminRuns);
    }

    [Fact]
    public async Task A_preflight_with_no_origin_needs_a_token()
    {
        // ASP.NET Core's CORS middleware passes an OPTIONS with no Origin on to the endpoint.
        using var response = await OptionsAsync("/v1/admin", ("Access-Control-Request-Method", "GET"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, _adminRuns);
    }

    [Theory]
    [InlineData("X-HTTP-Method-Override")]
    [InlineData("X-HTTP-Method")]
    [InlineData("X-Method-Override")]
    [InlineData("x-http-method-override")]
    public async Task A_preflight_with_a_method_override_header_needs_a_token(string header)
    {
        using var response = await OptionsAsync("/v1/admin", ("Origin", "https://app.example.test"), ("Access-Control-Request-Method", "GET"), (header, "GET"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, _adminRuns);
    }

    [Fact]
    public async Task A_post_that_use_http_method_override_turns_into_options_needs_a_token()
    {
        // UseHttpMethodOverride reads X-HTTP-Method-Override on a POST. The header stays on the
        // request, so the guard does not take it for a preflight.
        var runs = 0;
        var verifier = _issuer.Verifier(audience: Resource);
        await using var app = await TestApp.StartAsync(web =>
        {
            web.UseHttpMethodOverride();
            web.UseKeelieTokenGuard(verifier, _metadata);
            web.Map("/v1/admin", (HttpContext http) =>
            {
                Interlocked.Increment(ref runs);
                return Results.Ok(new { method = http.Request.Method });
            });
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/admin");
        request.Headers.TryAddWithoutValidation("X-HTTP-Method-Override", "OPTIONS");
        request.Headers.TryAddWithoutValidation("Origin", "https://app.example.test");
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "GET");

        using var response = await app.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, runs);
    }

    [Theory]
    // ASP.NET Core routes without case: the router serves these, and the guard must refuse them.
    [InlineData("/V1/orders/42", true)]
    [InlineData("/V1/ORDERS/42", true)]
    // Kestrel reads escapes and resolves dot segments before routing.
    [InlineData("/%76%31/orders/42", true)]
    [InlineData("/%56%31/orders/42", true)]
    [InlineData("/v1/../v1/orders/42", true)]
    [InlineData("/x/../v1/orders/42", true)]
    [InlineData("/v1/./orders/42", true)]
    [InlineData("/%2e%2e/v1/orders/42", true)]
    // Forms the router does not serve. Whatever their answer, it is never the endpoint's.
    [InlineData("//v1/orders/42", false)]
    [InlineData("/x/..%2fv1/orders/42", false)]
    [InlineData("/x/..%2Fv1/orders/42", false)]
    [InlineData("/v1%2forders/42", false)]
    public async Task Every_form_of_a_path_the_router_would_match_needs_a_token(string target, bool routed)
    {
        var status = await _app.RawStatusAsync(target);

        Assert.NotEqual(200, status);
        if (routed)
        {
            Assert.Equal(401, status);
        }
        else
        {
            Assert.True(status is 401 or 404 or 400, $"{target}: {status}");
        }
    }

    [Theory]
    [InlineData("/V1/orders/42")]
    [InlineData("/V1/ORDERS/42")]
    [InlineData("/%76%31/orders/42")]
    [InlineData("/%56%31/orders/42")]
    [InlineData("/x/../v1/orders/42")]
    [InlineData("/%2e%2e/v1/orders/42")]
    public async Task With_no_guard_the_router_does_serve_those_forms(string target)
    {
        // The control for the test above: each of these forms reaches the endpoint when nothing
        // guards it, so the guard's 401 is what stops it.
        await using var open = await TestApp.StartAsync(app => app.MapGet("/v1/orders/{orderId}", () => Results.Ok()));

        Assert.Equal(200, await open.RawStatusAsync(target));
    }

    [Fact]
    public async Task An_endpoint_whose_scope_check_has_no_token_guard_before_it_fails()
    {
        var scopes = new ScopeMap(new Dictionary<string, string> { ["GET /v1/orders/{orderId}"] = "orders:read" });
        await using var bare = await TestApp.StartAsync(app =>
            app.MapGet("/v1/orders/{orderId}", () => Results.Ok()).RequireKeelieScope(scopes, _metadata));

        using var response = await bare.SendAsync(HttpMethod.Get, "/v1/orders/1");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
    }
}

public sealed class GuardTests
{
    private const string MetadataUrl = "https://api.example.test/.well-known/oauth-protected-resource/api";
    private static readonly string ToolsList = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method = "tools/list" });

    private static void Adapter(WebApplication app, string adapter, TokenVerifier verifier, ProtectedResourceMetadata metadata)
    {
        if (adapter == "rest")
        {
            app.UseKeelieTokenGuard(verifier, metadata);
        }
        else
        {
            var reporter = new UsageReporter(new FakeKeelie().Client());
            app.UseKeelieMcpGuard(verifier, metadata, new Dictionary<string, string>(), reporter);
        }
    }

    public static TheoryData<string, string, int, string?> Tokens()
    {
        var data = new TheoryData<string, string, int, string?>();
        foreach (var adapter in new[] { "rest", "mcp" })
        {
            data.Add(adapter, "good", 200, null);
            data.Add(adapter, "none", 401, $"Bearer resource_metadata=\"{MetadataUrl}\"");
            data.Add(adapter, "expired", 401, "invalid_token");
            data.Add(adapter, "other org", 401, "invalid_token");
            data.Add(adapter, "other audience", 401, "invalid_token");
            data.Add(adapter, "other signer", 401, "invalid_token");
            data.Add(adapter, "not a token", 401, "invalid_token");
            data.Add(adapter, "header not UTF-8", 401, "invalid_token");
            data.Add(adapter, "payload not UTF-8", 401, "invalid_token");
            data.Add(adapter, "kid a lone surrogate", 401, "invalid_token");
            data.Add(adapter, "payload a lone surrogate", 401, "invalid_token");
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Tokens))]
    public async Task Both_adapters_answer_each_token_the_same(string adapter, string token, int status, string? challenge)
    {
        var (issuer, key) = StandardIssuer.Make();
        var metadata = new ProtectedResourceMetadata(Values.Audience, Values.Issuer);
        await using var app = await TestApp.StartAsync(web =>
        {
            Adapter(web, adapter, issuer.Verifier(), metadata);
            web.Run(context => context.Response.WriteAsync("{}"));
        });
        string? authorization = token switch
        {
            "good" => "Bearer " + Keelie.Tests.Tokens.Sign(key),
            "none" => null,
            "expired" => "Bearer " + Keelie.Tests.Tokens.Sign(key, new() { ["exp"] = Keelie.Tests.Tokens.Now - 31 }),
            "other org" => "Bearer " + Keelie.Tests.Tokens.Sign(key, new() { ["org_id"] = Guid.NewGuid().ToString() }),
            "other audience" => "Bearer " + Keelie.Tests.Tokens.Sign(key, new() { ["aud"] = "another-api" }),
            "other signer" => "Bearer " + Keelie.Tests.Tokens.Sign(new TestKey("sig-1")),
            // The header is {"alg":"RS256","kid":"<0xFF>"}.
            "header not UTF-8" => "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Iv8ifQ.e30.AA",
            "payload not UTF-8" => "Bearer " + Keelie.Tests.Tokens.SignWithRawMember(key, Keelie.Tests.Tokens.InvalidUtf8Member),
            "kid a lone surrogate" => "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ilx1ZDgwMCJ9.e30.AA",
            "payload a lone surrogate" => "Bearer " + Keelie.Tests.Tokens.SignWithRawMember(key, Keelie.Tests.Tokens.LoneSurrogateMember),
            _ => "Bearer not-a-token",
        };

        using var response = await app.SendAsync(HttpMethod.Post, "/api", authorization, ToolsList);

        Assert.Equal(status, (int)response.StatusCode);
        if (challenge == "invalid_token")
        {
            // One refusal for every reason: the reason goes to the log only.
            Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        }
        else if (challenge is not null)
        {
            Assert.Equal(challenge, response.Headers.WwwAuthenticate.ToString());
        }
        else
        {
            Assert.Empty(response.Headers.WwwAuthenticate);
        }
    }

    [Theory]
    [InlineData("rest")]
    [InlineData("mcp")]
    public async Task Neither_adapter_starts_for_an_audience_that_is_not_the_resource(string adapter)
    {
        // keelie writes the org's resource into aud (RFC 8707). A verifier for another audience would
        // refuse every token an agent asked for this resource.
        var metadata = new ProtectedResourceMetadata(Values.Audience, Values.Issuer);
        var elsewhere = new TokenVerifier(Values.Issuer, "https://api.example.test/other", Values.OrgId);

        var error = await Assert.ThrowsAsync<ArgumentException>(() => TestApp.StartAsync(app => Adapter(app, adapter, elsewhere, metadata)));

        Assert.Contains("is not the resource", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("rest")]
    [InlineData("mcp")]
    public async Task Neither_adapter_starts_for_an_issuer_that_is_not_the_authorization_server(string adapter)
    {
        // Agents get their tokens from the issuer the metadata names. A verifier for another issuer
        // would refuse every one of them.
        var metadata = new ProtectedResourceMetadata(Values.Audience, Values.Issuer);
        var elsewhere = new TokenVerifier("https://issuer.example.test/realms/other", Values.Audience, Values.OrgId);

        var error = await Assert.ThrowsAsync<ArgumentException>(() => TestApp.StartAsync(app => Adapter(app, adapter, elsewhere, metadata)));

        Assert.Contains("is not the authorization server", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("rest", "http://localhost:8080/realms/test")]
    [InlineData("mcp", "http://127.0.0.1:8080/realms/test")]
    [InlineData("rest", "http://[::1]:8080/realms/test")]
    public async Task Both_adapters_start_with_a_loopback_http_issuer(string adapter, string issuer)
    {
        var metadata = new ProtectedResourceMetadata(Values.Audience, issuer);
        await using var app = await TestApp.StartAsync(web =>
        {
            Adapter(web, adapter, new TokenVerifier(issuer, Values.Audience, Values.OrgId), metadata);
            web.Run(context => context.Response.WriteAsync("{}"));
        });

        using var response = await app.SendAsync(HttpMethod.Get, "/api");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(issuer, JsonDocument.Parse(metadata.Document).RootElement.GetProperty("authorization_servers")[0].GetString());
    }

    [Theory]
    [InlineData("rest", false, 401)]
    [InlineData("rest", true, 200)]
    [InlineData("mcp", false, 401)]
    [InlineData("mcp", true, 200)]
    public async Task Both_adapters_pass_only_a_real_preflight_with_no_token(string adapter, bool preflight, int status)
    {
        var runs = 0;
        var metadata = new ProtectedResourceMetadata(Values.Audience, Values.Issuer);
        await using var app = await TestApp.StartAsync(web =>
        {
            Adapter(web, adapter, new TokenVerifier(Values.Issuer, Values.Audience, Values.OrgId), metadata);
            web.Run(context =>
            {
                Interlocked.Increment(ref runs);
                return context.Response.WriteAsync("{}");
            });
        });
        using var request = new HttpRequestMessage(HttpMethod.Options, "/api");
        if (preflight)
        {
            request.Headers.TryAddWithoutValidation("Origin", "https://app.example.test");
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
        }

        using var response = await app.Http.SendAsync(request);

        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(preflight ? 1 : 0, runs);
    }

    [Theory]
    [InlineData("rest")]
    [InlineData("mcp")]
    public async Task A_path_outside_the_resource_passes_both_adapters_untouched(string adapter)
    {
        var bodies = new List<string>();
        var metadata = new ProtectedResourceMetadata(Values.Audience, Values.Issuer);
        await using var app = await TestApp.StartAsync(web =>
        {
            Adapter(web, adapter, new TokenVerifier(Values.Issuer, Values.Audience, Values.OrgId), metadata);
            web.Run(async context =>
            {
                bodies.Add(await new StreamReader(context.Request.Body).ReadToEndAsync());
                await context.Response.WriteAsync("{}");
            });
        });

        using var response = await app.SendAsync(HttpMethod.Post, "/health", body: "{not json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(["{not json"], bodies);
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task With_a_resource_at_the_root_only_a_get_or_head_of_the_metadata_needs_no_token(string method)
    {
        const string Root = "https://api.example.test";
        var metadata = new ProtectedResourceMetadata(Root, Values.Issuer);
        await using var app = await TestApp.StartAsync(web =>
        {
            web.UseKeelieTokenGuard(new TokenVerifier(Values.Issuer, Root, Values.OrgId), metadata);
            web.Run(context => context.Response.WriteAsync("{}"));
        });

        using var get = await app.SendAsync(HttpMethod.Get, "/.well-known/oauth-protected-resource");
        using var other = await app.SendAsync(new HttpMethod(method), "/.well-known/oauth-protected-resource");
        using var orders = await app.SendAsync(HttpMethod.Get, "/orders");

        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(Root, JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement.GetProperty("resource").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, other.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, orders.StatusCode);
        Assert.Equal(
            "Bearer resource_metadata=\"https://api.example.test/.well-known/oauth-protected-resource\"",
            orders.Headers.WwwAuthenticate.ToString());
    }
}

/// <summary>
/// keelie is unreachable for 20 minutes, and Consumers call the Provider's API. The token carries the
/// decision: the SDK serves every call while a token lives, and refuses when it expires. It asks
/// keelie for nothing on the way.
/// </summary>
public sealed class OutageTests
{
    private const string Resource = "https://api.example.test/api";

    // What each Consumer holds when it calls, 20 minutes into the outage. A token expired more than
    // the 30 seconds of leeway ago is refused.
    [Theory]
    [InlineData("large balance", 3600, 200)]
    [InlineData("balance reaches zero, token alive", 120, 200)]
    [InlineData("balance reaches zero, token expired", -31, 401)]
    [InlineData("delinquent", -600, 401)]
    [InlineData("never seen", null, 401)]
    public async Task Consumers_during_a_20_minute_outage(string consumer, int? expiresIn, int status)
    {
        var (issuer, key) = StandardIssuer.Make();
        var clock = new ManualClock();
        var verifier = issuer.Verifier(clock, Resource);
        await using var app = await TestApp.StartAsync(web =>
        {
            web.UseKeelieTokenGuard(verifier, new ProtectedResourceMetadata(Resource, Values.Issuer));
            web.Run(context => context.Response.WriteAsync("{}"));
        });
        // Before the outage, one call loads the issuer's keys.
        using var warm = await app.SendAsync(HttpMethod.Get, "/api", "Bearer " + Tokens.Sign(key, new() { ["aud"] = Resource }));
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);

        issuer.Down = true;
        clock.Advance(TimeSpan.FromMinutes(20));
        var authorization = expiresIn is { } seconds
            ? "Bearer " + Tokens.Sign(key, new() { ["aud"] = Resource, ["exp"] = Tokens.Now + seconds })
            : null;
        using var response = await app.SendAsync(HttpMethod.Get, "/api", authorization);

        Assert.True(status == (int)response.StatusCode, consumer);
        // The SDK asked the issuer nothing during the outage: the keys in hand did the work.
        Assert.Equal(1, issuer.JwksFetches);
        // So the status does not show the outage: the SDK does not poll.
        Assert.Equal(IssuerStatus.Connected, verifier.Status);
    }
}
