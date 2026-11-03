// The example of docs/dotnet.md, "Get started with ASP.NET Core". It is compiled with the tests,
// and never run, so the example cannot drift from the package. Keep the two the same.

using Keelie;
using Keelie.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keelie.Tests;

internal static class DocExample
{
    private static string Env(string name) =>
        Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"{name} is not set");

    internal static async Task RunAsync(string[] args)
    {
        // --- docs/dotnet.md starts here ---
        using var keelie = SdkCredential.CreateClient(new SdkCredentialOptions
        {
            KeelieUrl = Env("KEELIE_URL"),
            TokenUrl = Env("KEELIE_TOKEN_URL"),
            ClientId = Env("KEELIE_SDK_CLIENT_ID"),
            ClientSecret = Env("KEELIE_SDK_CLIENT_SECRET"),
        });
        var verifier = new TokenVerifier(Env("KEELIE_ISSUER"), Env("KEELIE_RESOURCE"), Env("KEELIE_ORG_ID"));
        var metadata = new ProtectedResourceMetadata(Env("KEELIE_RESOURCE"), Env("KEELIE_ISSUER"));
        var scopes = new ScopeMap(new Dictionary<string, string>
        {
            ["GET /v1/orders/{orderId}"] = "orders:read",
        });
        await using var reporter = new UsageReporter(keelie);

        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();
        KeelieLogging.LoggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
        app.UseKeelieTokenGuard(verifier, metadata);

        app.MapGet("/v1/orders/{orderId}", (string orderId, HttpContext http) =>
        {
            var claims = http.GetKeelieClaims()!;
            reporter.Record(claims.Azp, "GET /v1/orders/{orderId}", credits: 1, consumerId: claims.ConsumerId);
            return Results.Ok(new { orderId });
        }).RequireKeelieScope(scopes, metadata);

        reporter.Start();
        await app.RunAsync();
        // --- docs/dotnet.md ends here ---
    }
}
