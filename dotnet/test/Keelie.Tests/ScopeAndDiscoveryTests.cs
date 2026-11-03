namespace Keelie.Tests;

public sealed class ScopeTests
{
    private static readonly ScopeMap Scopes = new(new Dictionary<string, string>
    {
        ["GET /orders/{orderId}"] = "orders:read",
        ["POST /orders"] = "orders:write",
    });

    private static Claims ClaimsWith(string scope) =>
        new("client-1", Values.OrgId, new HashSet<string>(scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)), null, DateTimeOffset.UtcNow);

    [Theory]
    [InlineData("GET", "/orders/{orderId}")]
    [InlineData("get", "/orders/{orderId}")]
    [InlineData("POST", "/orders")]
    public void A_token_with_the_scope_passes(string method, string route)
    {
        Scopes.Check(ClaimsWith("orders:read orders:write"), method, route);
    }

    [Theory]
    // No scope, or another route's scope.
    [InlineData("", "GET", "/orders/{orderId}")]
    [InlineData("orders:write", "GET", "/orders/{orderId}")]
    // A scope matches only itself: no prefix, no parent.
    [InlineData("orders", "GET", "/orders/{orderId}")]
    [InlineData("orders:read:all", "GET", "/orders/{orderId}")]
    // A route matches only itself: another method, a concrete path, a sub-path, another case.
    [InlineData("orders:read orders:write", "DELETE", "/orders/{orderId}")]
    [InlineData("orders:read orders:write", "GET", "/orders/42")]
    [InlineData("orders:read orders:write", "POST", "/orders/")]
    [InlineData("orders:read orders:write", "POST", "/orders/{orderId}/items")]
    [InlineData("orders:read orders:write", "POST", "/Orders")]
    public void A_token_without_the_scope_is_refused(string scope, string method, string route)
    {
        var refused = Assert.Throws<InsufficientScope>(() => Scopes.Check(ClaimsWith(scope), method, route));

        // A 403, not a 401: a caller that maps TokenRejected to 401 must not catch it.
        Assert.IsNotType<TokenRejected>(refused, exactMatch: false);
        Assert.Equal(method.ToUpperInvariant(), refused.Method);
    }

    [Fact]
    public void The_method_in_the_map_is_case_insensitive()
    {
        new ScopeMap(new Dictionary<string, string> { ["get /orders"] = "orders:read" }).Check(ClaimsWith("orders:read"), "GET", "/orders");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(" orders:read")]
    [InlineData("orders:read ")]
    [InlineData("orders:read orders:write")]
    [InlineData("orders:read\torders:write")]
    [InlineData("orders:read\u001forders:write")]
    public void A_route_requires_exactly_one_scope(string scope)
    {
        var error = Assert.Throws<ArgumentException>(() => new ScopeMap(new Dictionary<string, string> { ["GET /orders"] = scope }));

        Assert.Contains("not one scope", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_route_given_twice_is_refused()
    {
        // The method is case-insensitive, so these two are one route with two scopes.
        var error = Assert.Throws<ArgumentException>(() => new ScopeMap(new Dictionary<string, string>
        {
            ["get /orders"] = "orders:write",
            ["GET /orders"] = "orders:read",
        }));

        Assert.Contains("route given twice", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("GET ")]
    [InlineData(" /orders")]
    public void A_key_that_is_not_a_method_and_a_route_is_refused(string entry)
    {
        Assert.Throws<ArgumentException>(() => new ScopeMap(new Dictionary<string, string> { [entry] = "orders:read" }));
    }
}

public sealed class DiscoveryTests
{
    private const string Resource = "https://api.example.test/mcp";
    private const string MetadataUrl = "https://api.example.test/.well-known/oauth-protected-resource/mcp";

    [Fact]
    public void The_metadata_names_the_resource_and_one_issuer()
    {
        var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer);

        Assert.Equal("/.well-known/oauth-protected-resource/mcp", metadata.Path);
        Assert.Equal(MetadataUrl, metadata.Url);
        Assert.Equal(
            "{\"resource\":\"https://api.example.test/mcp\",\"authorization_servers\":[\"https://issuer.example.test/realms/test\"],\"bearer_methods_supported\":[\"header\"]}",
            metadata.Document);
    }

    [Fact]
    public void The_challenges_name_the_metadata()
    {
        var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer);

        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", metadata.Challenge());
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", metadata.Challenge("invalid_token"));
        Assert.Throws<ArgumentException>(() => metadata.Challenge("Invalid Token"));
    }

    [Fact]
    public void A_resource_at_the_root_has_its_metadata_at_the_well_known_root()
    {
        var metadata = new ProtectedResourceMetadata("https://api.example.test", Values.Issuer);

        Assert.Equal("/.well-known/oauth-protected-resource", metadata.Path);
        Assert.True(metadata.Protects("/anything"));
    }

    [Theory]
    [InlineData("/mcp", true)]
    [InlineData("/mcp/tools", true)]
    [InlineData("/mcpx", false)]
    [InlineData("/health", false)]
    [InlineData("/MCP", false)]
    public void Protects_is_the_path_of_the_resource_and_every_path_below_it(string path, bool protects)
    {
        Assert.Equal(protects, new ProtectedResourceMetadata(Resource, Values.Issuer).Protects(path));
    }

    [Theory]
    [InlineData("http://api.example.test/mcp")]
    [InlineData("https://api.example.test/mcp?x=1")]
    [InlineData("https://api.example.test/mcp?")]
    [InlineData("https://api.example.test/mcp#x")]
    [InlineData("https://api.example.test/m\"cp")]
    [InlineData("https://api.example.test/m cp")]
    [InlineData("https://user:secret@api.example.test/mcp")]
    [InlineData("https://api.example.test:port/mcp")]
    [InlineData("https://api.example.test:70000/mcp")]
    [InlineData("https://api.example.test/mcp/")]
    [InlineData("https:///mcp")]
    [InlineData("/mcp")]
    [InlineData("")]
    // keelie compares aud exactly with the resource it stored, which is lowercase.
    [InlineData("HTTPS://api.example.test/mcp")]
    [InlineData("https://API.example.test/mcp")]
    public void A_resource_that_is_not_a_plain_https_url_is_refused(string resource)
    {
        Assert.Throws<ArgumentException>(() => new ProtectedResourceMetadata(resource, Values.Issuer));
    }

    [Theory]
    [InlineData("https://api.example.test:8443/mcp")]
    [InlineData("https://[::1]:8443/mcp")]
    [InlineData("https://api.example.test/")]
    [InlineData("https://api.example.test/V1/Orders")]
    public void A_plain_https_url_is_taken(string resource)
    {
        Assert.Equal(resource, new ProtectedResourceMetadata(resource, Values.Issuer).Resource);
    }

    [Fact]
    public void Scopes_are_published_only_when_given_and_one_scope_each()
    {
        var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer, ["orders:read", "ünï"]);

        Assert.EndsWith(",\"scopes_supported\":[\"orders:read\",\"\\u00fcn\\u00ef\"]}", metadata.Document, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => new ProtectedResourceMetadata(Resource, Values.Issuer, ["orders:read orders:write"]));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("Basic dXNlcjpwYXNz", null)]
    [InlineData("Bearer ", null)]
    [InlineData("Bearer", null)]
    [InlineData("bearer  ", null)]
    [InlineData("Bearer\tx", null)]
    [InlineData("Bearer x", "x")]
    [InlineData("bearer x", "x")]
    [InlineData("  BEARER   x  ", "x")]
    public void The_bearer_token_is_read_as_the_python_sdk_reads_it(string? header, string? token)
    {
        Assert.Equal(token, ProtectedResourceMetadata.BearerToken(header));
    }
}
