using System.Net;
using System.Text;
using System.Text.Json;
using Keelie.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Client;
using ModelContextProtocol.Server;

namespace Keelie.Tests;

/// <summary>The guard in front of a stand-in MCP server, which keeps each body and answers as told.</summary>
[Collection("logs")]
public sealed class McpGuardTests : IAsyncLifetime
{
    private const string Resource = "https://api.example.test/mcp";
    private const string MetadataUrl = "https://api.example.test/.well-known/oauth-protected-resource/mcp";

    // Each tool and its one scope. Inside the adapter, the ScopeMap key of a tool is
    // ("tools/call", <tool name>).
    private static readonly Dictionary<string, string> Tools = new()
    {
        ["get_order"] = "orders:read",
        ["cancel_order"] = "orders:write",
    };

    private readonly FakeIssuer _issuer;
    private readonly TestKey _key;
    private readonly FakeKeelie _keelie = new();
    private readonly List<byte[]> _bodies = [];
    private UsageReporter _reporter = null!;
    private TestApp _app = null!;
    private int _status = 200;
    private bool _sse;

    public McpGuardTests() => (_issuer, _key) = StandardIssuer.Make();

    public async ValueTask InitializeAsync()
    {
        LogCapture.Clear();
        _reporter = new UsageReporter(_keelie.Client());
        _app = await TestApp.StartAsync(app =>
        {
            app.UseKeelieMcpGuard(_issuer.Verifier(audience: Resource), new ProtectedResourceMetadata(Resource, Values.Issuer), Tools, _reporter, maxBodyBytes: 1024 * 1024);
            app.Run(async context =>
            {
                using var body = new MemoryStream();
                await context.Request.Body.CopyToAsync(body);
                lock (_bodies)
                {
                    _bodies.Add(body.ToArray());
                }
                context.Response.StatusCode = _status;
                context.Response.ContentType = _sse ? "text/event-stream" : "application/json";
                if (_sse)
                {
                    await context.Response.WriteAsync("data: 1\n\n");
                    await context.Response.Body.FlushAsync();
                    await context.Response.WriteAsync("data: 2\n\n");
                }
                else
                {
                    await context.Response.WriteAsync("{}");
                }
            });
        });
    }

    public async ValueTask DisposeAsync()
    {
        await _reporter.CloseAsync();
        await _app.DisposeAsync();
    }

    private string Auth(string scope = "orders:read orders:write", Dictionary<string, object?>? extra = null)
    {
        var claims = new Dictionary<string, object?> { ["aud"] = Resource, ["scope"] = scope };
        foreach (var (name, value) in extra ?? [])
        {
            claims[name] = value;
        }
        return "Bearer " + Tokens.Sign(_key, claims);
    }

    private static string Call(object? tool, object? id = null, bool withId = true)
    {
        var request = new Dictionary<string, object?> { ["jsonrpc"] = "2.0" };
        if (withId)
        {
            request["id"] = id ?? 7;
        }
        request["method"] = "tools/call";
        request["params"] = new Dictionary<string, object?> { ["name"] = tool };
        return JsonSerializer.Serialize(request);
    }

    private async Task<HttpResponseMessage> PostAsync(string body, string? authorization = null) =>
        await _app.SendAsync(HttpMethod.Post, "/mcp", authorization ?? Auth(), body);

    private async Task<HttpResponseMessage> PostBytesAsync(byte[] body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = new ByteArrayContent(body) };
        request.Headers.TryAddWithoutValidation("Authorization", Auth());
        return await _app.Http.SendAsync(request);
    }

    private List<Dictionary<string, string>> Events => _keelie.Batches().SelectMany(batch => batch).ToList();

    [Fact]
    public async Task A_tool_call_with_the_scope_reaches_the_server_unchanged()
    {
        var body = Call("get_order");

        using var response = await PostAsync(body, Auth("orders:read"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([body], _bodies.Select(b => Encoding.UTF8.GetString(b)));
    }

    [Theory]
    [InlineData("get_order", "orders:write")] // another tool's scope
    [InlineData("get_order", "")]
    [InlineData("get_order", "orders")] // a scope matches only itself
    [InlineData("GET_ORDER", "orders:read orders:write")] // a tool name matches only itself
    [InlineData("unmapped", "orders:read orders:write")] // not in the map: refused
    [InlineData("x\napiable.forged line", "orders:read orders:write")] // stays out of the log
    public async Task A_token_without_the_tools_scope_cannot_call_it(string tool, string scope)
    {
        using var response = await PostAsync(Call(tool), Auth(scope));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal($"Bearer error=\"insufficient_scope\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
        // The same answer for an unmapped tool and an unscoped one: no scope is named.
        Assert.Equal("{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-31001,\"message\":\"Insufficient scope\"}}", await response.Content.ReadAsStringAsync());
        Assert.Empty(_bodies);
        // A tool name that is not in the map comes from the request: it is not logged.
        Assert.DoesNotContain("forged", LogCapture.Text, StringComparison.Ordinal);
        Assert.Contains("apiable.mcp_refused status=403 code=-31001", LogCapture.Text, StringComparison.Ordinal);
    }

    public static TheoryData<string, byte[], int, int, string?> BadBodies()
    {
        static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
        return new TheoryData<string, byte[], int, int, string?>
        {
            { "not json", Utf8("{not json"), 400, -32700, null },
            { "not utf-8", [0xff, 0xfe], 400, -32700, null },
            { "too deep", Utf8(new string('[', 200_000) + new string(']', 200_000)), 400, -32700, null },
            { "1001 deep", Utf8(new string('[', 1001) + new string(']', 1001)), 400, -32700, null },
            { "byte order mark", Utf8("\uFEFF{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"), 400, -32700, null },
            { "two values", Utf8("{} {}"), 400, -32700, null },
            { "a batch", Utf8("[" + Call("get_order") + "]"), 400, -32600, null },
            { "a number", Utf8("1"), 400, -32600, null },
            { "a string", Utf8("\"just a string\""), 400, -32600, null },
            { "a key twice", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"get_order\",\"name\":\"cancel_order\"}}"), 400, -32600, null },
            { "a key twice, escaped", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"get_order\",\"\\u006eame\":\"cancel_order\"}}"), 400, -32600, null },
            { "method in another case", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"Method\":\"tools/call\",\"params\":{\"name\":\"cancel_order\"}}"), 400, -32600, null },
            { "method beside another case", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\",\"METHOD\":\"tools/call\",\"params\":{\"name\":\"cancel_order\"}}"), 400, -32600, null },
            { "params in another case", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"get_order\"},\"Params\":{\"name\":\"cancel_order\"}}"), 400, -32600, null },
            { "id in another case", Utf8("{\"jsonrpc\":\"2.0\",\"ID\":7,\"method\":\"ping\"}"), 400, -32600, null },
            { "name beside another case", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"get_order\",\"Name\":\"cancel_order\"}}"), 400, -32600, null },
            { "name in another case", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"NAME\":\"cancel_order\"}}"), 400, -32600, null },
            { "no id", Utf8("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"get_order\"}}"), 400, -32600, null },
            { "id null", Utf8(Call("get_order", withId: true, id: null).Replace("\"id\":7", "\"id\":null", StringComparison.Ordinal)), 400, -32600, null },
            { "id true", Utf8(Call("get_order", true)), 400, -32600, null },
            { "id a decimal", Utf8(Call("get_order", 7.5)), 400, -32600, null },
            { "name a number", Utf8(Call(42)), 400, -32602, "7" },
            { "no params", Utf8("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}"), 400, -32602, "7" },
            { "string id echoed", Utf8("{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"tools/call\",\"params\":{\"name\":3}}"), 400, -32602, "\"a\"" },
            { "too large", Utf8(Call(new string('x', 1024 * 1024))), 413, -32600, null },
        };
    }

    [Theory]
    [MemberData(nameof(BadBodies))]
    public async Task A_body_the_adapter_cannot_check_is_refused_with_a_json_rpc_error(string name, byte[] body, int status, int code, string? id)
    {
        using var response = await PostBytesAsync(body);

        Assert.True(status == (int)response.StatusCode, name);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.ToString());
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("2.0", problem.RootElement.GetProperty("jsonrpc").GetString());
        Assert.Equal(id ?? "null", problem.RootElement.GetProperty("id").GetRawText());
        Assert.Equal(code, problem.RootElement.GetProperty("error").GetProperty("code").GetInt32());
        Assert.Empty(_bodies);
    }

    [Theory]
    [InlineData("initialize")]
    [InlineData("notifications/initialized")]
    [InlineData("ping")]
    [InlineData("tools/list")]
    [InlineData("resources/read")]
    public async Task Other_methods_pass_with_no_scope_and_count_nothing(string method)
    {
        var body = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method });

        using var response = await PostAsync(body, Auth(""));
        await _reporter.CloseAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([body], _bodies.Select(b => Encoding.UTF8.GetString(b)));
        Assert.Empty(Events);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    public async Task A_get_or_a_delete_passes_after_the_token_check(string method)
    {
        using var refused = await _app.SendAsync(new HttpMethod(method), "/mcp");
        using var response = await _app.SendAsync(new HttpMethod(method), "/mcp", Auth(""));

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([""], _bodies.Select(b => Encoding.UTF8.GetString(b)));
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    public async Task Another_method_with_a_tool_call_gets_405(string method)
    {
        using var response = await _app.SendAsync(new HttpMethod(method), "/mcp", Auth(""), Call("get_order"));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Equal("GET, POST, DELETE", response.Content.Headers.Allow.Count > 0 ? string.Join(", ", response.Content.Headers.Allow) : response.Headers.GetValues("Allow").Single());
        Assert.Empty(_bodies);
    }

    [Theory]
    [InlineData(200, true, 1)]
    [InlineData(200, false, 1)]
    [InlineData(500, false, 0)]
    public async Task One_event_for_each_tool_call_the_server_accepts(int status, bool sse, int counted)
    {
        _status = status;
        _sse = sse;

        using var response = await PostAsync(Call("get_order"));
        var text = await response.Content.ReadAsStringAsync();
        await _reporter.CloseAsync();

        Assert.Equal(status, (int)response.StatusCode);
        if (sse)
        {
            // The stream reaches the client unchanged.
            Assert.Equal("data: 1\n\ndata: 2\n\n", text);
        }
        Assert.Equal(
            Enumerable.Repeat(("client-1", "get_order", "tool_call"), counted),
            Events.Select(e => (e["client_id"], e["capability_key"], e["unit"])));
        Assert.All(Events, e => Assert.False(e.ContainsKey("credits")));
    }

    [Fact]
    public async Task A_tool_call_under_a_token_for_a_person_names_its_consumer()
    {
        var consumer = Guid.NewGuid();

        using var response = await PostAsync(Call("get_order"), Auth(extra: new() { ["consumer_id"] = consumer.ToString() }));
        await _reporter.CloseAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([consumer.ToString()], Events.Select(e => e["consumer_id"]));
    }
}

/// <summary>A real MCP client and a real MCP server, both from the official C# SDK, with the guard between them.</summary>
public sealed class McpSdkTests
{
    private const string Resource = "https://api.example.test/mcp";

    [Fact]
    public async Task A_real_mcp_client_lists_and_calls_a_tool_its_token_allows_and_the_call_is_counted()
    {
        var (issuer, key) = StandardIssuer.Make();
        var keelie = new FakeKeelie();
        await using var reporter = new UsageReporter(keelie.Client(), new UsageReporterOptions { BatchSize = 1, FlushInterval = TimeSpan.FromMilliseconds(20) });
        var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer);
        var tools = new Dictionary<string, string> { ["classify"] = "classify:run", ["delete_all"] = "admin" };
        var methods = new List<string>();
        await using var app = await TestApp.StartAsync(
            web =>
            {
                web.Use(async (context, next) =>
                {
                    lock (methods)
                    {
                        methods.Add(context.Request.Method);
                    }
                    await next(context);
                });
                web.UseKeelieMcpGuard(issuer.Verifier(audience: Resource), metadata, tools, reporter);
                web.MapMcp("/mcp");
            },
            services => services.AddMcpServer().WithHttpTransport().WithTools(
            [
                McpServerTool.Create(() => "Apparel > Shoes", new McpServerToolCreateOptions { Name = "classify", Description = "Classify a product" }),
                McpServerTool.Create(() => "gone", new McpServerToolCreateOptions { Name = "delete_all", Description = "Delete everything" }),
            ]));
        var consumer = Guid.NewGuid();
        var token = Tokens.Sign(key, new()
        {
            ["aud"] = Resource,
            ["scope"] = "classify:run",
            ["azp"] = "claude",
            ["consumer_id"] = consumer.ToString(),
        });

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(app.Url, "/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" },
        });
        await using (var client = await McpClient.CreateAsync(transport))
        {
            var listed = await client.ListToolsAsync();
            Assert.Equal(["classify", "delete_all"], listed.Select(t => t.Name).Order());

            var result = await client.CallToolAsync("classify", new Dictionary<string, object?>());
            var text = Assert.IsType<ModelContextProtocol.Protocol.TextContentBlock>(Assert.Single(result.Content));
            Assert.Equal("Apparel > Shoes", text.Text);

            await Assert.ThrowsAnyAsync<Exception>(() => client.CallToolAsync("delete_all", new Dictionary<string, object?>()).AsTask());
        }

        await reporter.CloseAsync();
        var calls = keelie.Batches().SelectMany(batch => batch).Where(e => e["unit"] == "tool_call").ToList();
        var call = Assert.Single(calls);
        Assert.Equal("classify", call["capability_key"]);
        Assert.Equal("claude", call["client_id"]);
        Assert.Equal(consumer.ToString(), call["consumer_id"]);
        Assert.False(call.ContainsKey("credits"));
        Assert.Contains("POST", methods);
    }

    [Fact]
    public async Task A_key_in_another_case_reaches_no_tool_of_a_real_mcp_server()
    {
        // The SDK's server reads the params of a tool call without regard to case. A body whose
        // keys differ from the guard's only in case is refused before it gets there.
        var (issuer, key) = StandardIssuer.Make();
        await using var reporter = new UsageReporter(new FakeKeelie().Client());
        var tools = new Dictionary<string, string> { ["classify"] = "classify:run", ["delete_all"] = "admin" };
        var ran = new List<string>();
        await using var app = await TestApp.StartAsync(
            web =>
            {
                web.UseKeelieMcpGuard(issuer.Verifier(audience: Resource), new ProtectedResourceMetadata(Resource, Values.Issuer), tools, reporter);
                web.MapMcp("/mcp");
            },
            services => services.AddMcpServer().WithHttpTransport(options => options.Stateless = true).WithTools(
            [
                McpServerTool.Create(() => Ran(ran, "classify"), new McpServerToolCreateOptions { Name = "classify" }),
                McpServerTool.Create(() => Ran(ran, "delete_all"), new McpServerToolCreateOptions { Name = "delete_all" }),
            ]));
        var token = Tokens.Sign(key, new() { ["aud"] = Resource, ["scope"] = "classify:run" });

        async Task<HttpStatusCode> PostAsync(string body)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
            request.Headers.TryAddWithoutValidation("Accept", "application/json, text/event-stream");
            using var response = await app.Http.SendAsync(request);
            await response.Content.ReadAsStringAsync();
            return response.StatusCode;
        }

        Assert.Equal(HttpStatusCode.OK, await PostAsync("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"classify\",\"arguments\":{}}}"));
        Assert.Equal(["classify"], ran);
        ran.Clear();
        string[] variants =
        [
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"Method\":\"tools/call\",\"params\":{\"name\":\"delete_all\",\"arguments\":{}}}",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"classify\",\"Name\":\"delete_all\",\"arguments\":{}}}",
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"Name\":\"delete_all\",\"name\":\"classify\",\"arguments\":{}}}",
            "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"classify\",\"arguments\":{}},\"Params\":{\"name\":\"delete_all\",\"arguments\":{}}}",
        ];
        foreach (var body in variants)
        {
            Assert.Equal(HttpStatusCode.BadRequest, await PostAsync(body));
        }
        Assert.Empty(ran);
    }

    private static string Ran(List<string> ran, string tool)
    {
        lock (ran)
        {
            ran.Add(tool);
        }
        return "ok";
    }

    [Fact]
    public async Task A_real_mcp_client_with_no_token_is_refused_and_told_where_the_metadata_is()
    {
        var (issuer, _) = StandardIssuer.Make();
        await using var reporter = new UsageReporter(new FakeKeelie().Client());
        var metadata = new ProtectedResourceMetadata(Resource, Values.Issuer);
        await using var app = await TestApp.StartAsync(
            web =>
            {
                web.UseKeelieMcpGuard(issuer.Verifier(audience: Resource), metadata, new Dictionary<string, string>(), reporter);
                web.MapMcp("/mcp");
            },
            services => services.AddMcpServer().WithHttpTransport());

        using var response = await app.SendAsync(HttpMethod.Post, "/mcp", body: "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(metadata.Challenge(), response.Headers.WwwAuthenticate.ToString());
    }
}
