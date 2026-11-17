using System.Net;
using Keelie.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Keelie.Tests;

/// <summary>
/// An app behind <c>UsePathBase</c> routes a path with the base and without it. The guard must see
/// the resource whichever way the request comes, and so behind a proxy that strips a prefix.
/// </summary>
public sealed class PathBaseTests
{
    private const string Resource = "https://api.example.test/api/v1";

    private static async Task<(TestApp App, Func<int> Hits, TestKey Key)> StartAsync(bool guard, string? pathBase, string resource = Resource)
    {
        var hits = 0;
        var (issuer, key) = StandardIssuer.Make();
        var app = await TestApp.StartAsync(web =>
        {
            if (pathBase is not null)
            {
                web.UsePathBase(pathBase);
                web.UseRouting();
            }
            if (guard)
            {
                web.UseKeelieTokenGuard(issuer.Verifier(audience: resource), new ProtectedResourceMetadata(resource, Values.Issuer));
            }
            web.MapGet("/v1/orders/{orderId}", () =>
            {
                Interlocked.Increment(ref hits);
                return Results.Ok();
            });
            web.MapGet("/health", () => Results.Ok());
        });
        return (app, () => Volatile.Read(ref hits), key);
    }

    [Theory]
    [InlineData("/api/v1/orders/42")]
    [InlineData("/v1/orders/42")]
    [InlineData("/API/V1/orders/42")]
    [InlineData("/V1/orders/42")]
    public async Task With_no_guard_usepathbase_routes_the_path_with_and_without_the_base(string target)
    {
        // The control: each of these reaches the endpoint when nothing guards it.
        var (app, hits, _) = await StartAsync(guard: false, pathBase: "/api");
        await using (app)
        {
            Assert.Equal(200, await app.RawStatusAsync(target));
            Assert.Equal(1, hits());
        }
    }

    [Theory]
    [InlineData("/api/v1/orders/42")]
    [InlineData("/v1/orders/42")]
    [InlineData("/API/V1/orders/42")]
    [InlineData("/V1/orders/42")]
    [InlineData("/%76%31/orders/42")]
    public async Task Behind_usepathbase_a_request_with_or_without_the_base_needs_a_token(string target)
    {
        var (app, hits, _) = await StartAsync(guard: true, pathBase: "/api");
        await using (app)
        {
            Assert.Equal(401, await app.RawStatusAsync(target));
            Assert.Equal(0, hits());
            Assert.Equal(200, await app.RawStatusAsync("/health"));
        }
    }

    [Theory]
    [InlineData("/api/v1/orders/42")]
    [InlineData("/v1/orders/42")]
    public async Task Behind_usepathbase_a_good_token_reaches_the_endpoint_both_ways(string target)
    {
        var (app, hits, key) = await StartAsync(guard: true, pathBase: "/api");
        await using (app)
        {
            var token = "Bearer " + Tokens.Sign(key, new() { ["aud"] = Resource });
            Assert.Equal(200, await app.RawStatusAsync(target, authorization: token));
            Assert.Equal(1, hits());
        }
    }

    [Fact]
    public async Task Behind_a_proxy_that_strips_the_base_the_stripped_path_needs_a_token()
    {
        // No UsePathBase: the app sees /v1/... only, while the resource is /api/v1.
        var (app, hits, _) = await StartAsync(guard: true, pathBase: null);
        await using (app)
        {
            Assert.Equal(401, await app.RawStatusAsync("/v1/orders/42"));
            Assert.Equal(0, hits());
        }
    }

    [Theory]
    [InlineData("/api/v1/orders/42")]
    [InlineData("/v1/orders/42")]
    public async Task Behind_usepathbase_a_resource_without_the_base_is_guarded_both_ways(string target)
    {
        var (app, hits, _) = await StartAsync(guard: true, pathBase: "/api", resource: "https://api.example.test/v1");
        await using (app)
        {
            Assert.Equal(401, await app.RawStatusAsync(target));
            Assert.Equal(0, hits());
        }
    }
}
