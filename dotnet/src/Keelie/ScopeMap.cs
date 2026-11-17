using System.Text.Json;

namespace Keelie;

/// <summary>
/// The token does not carry the scope the route requires, or the route is not in the map. Answer
/// it with <c>403</c>, not <c>401</c>: the token is good, it does not allow this call.
/// </summary>
public sealed class InsufficientScope : Exception
{
    /// <summary>A refusal of <paramref name="method"/> <paramref name="route"/>.</summary>
    public InsufficientScope(string method, string route)
        : base($"{method} {route}")
    {
        Method = method;
        Route = route;
    }

    /// <summary>The method of the refused call, in capitals.</summary>
    public string Method { get; }

    /// <summary>The route of the refused call, as it was checked.</summary>
    public string Route { get; }
}

/// <summary>
/// The scope that each route requires.
/// </summary>
/// <remarks>
/// You give the SDK one map: for each route, the scope a token must carry. A route is the HTTP
/// method and the route template your framework matched, such as
/// <c>"GET /v1/orders/{orderId}"</c>. Give the template, not the path of the request, so that one
/// entry covers every order.
/// <para>The check is strict:</para>
/// <list type="bullet">
/// <item>A scope matches only itself. <c>orders:read</c> does not grant <c>orders</c>, and
/// <c>orders</c> does not grant <c>orders:read</c>.</item>
/// <item>A route matches only itself. There is no prefix and no wildcard.</item>
/// <item>A route that is not in the map is refused. Add every route that a token may call.</item>
/// </list>
/// </remarks>
public sealed class ScopeMap
{
    private const string Category = "Keelie.ScopeMap";

    private readonly Dictionary<(string Method, string Route), string> _routes = new();

    /// <summary>
    /// A map from each <c>"METHOD /template"</c> to its one scope, such as
    /// <c>["GET /v1/orders/{orderId}"] = "orders:read"</c>. The method and the template are split
    /// at the first space. The method is read in any case.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// A key is not a method and a template, a value is not exactly one scope, or a route is given
    /// twice.
    /// </exception>
    public ScopeMap(IEnumerable<KeyValuePair<string, string>> routes)
    {
        ArgumentNullException.ThrowIfNull(routes);
        foreach (var (entry, scope) in routes)
        {
            var at = entry.IndexOf(' ', StringComparison.Ordinal);
            if (at <= 0 || at == entry.Length - 1)
            {
                throw new ArgumentException($"not \"METHOD /route\": {JsonSerializer.Serialize(entry)}", nameof(routes));
            }
            Add(entry[..at], entry[(at + 1)..], scope);
        }
    }

    private void Add(string method, string route, string scope)
    {
        if (!Compat.IsOneScope(scope))
        {
            throw new ArgumentException($"not one scope: {JsonSerializer.Serialize(scope)} for {method} {route}");
        }
        if (!_routes.TryAdd((method.ToUpperInvariant(), route), scope))
        {
            throw new ArgumentException($"route given twice: {method} {route}");
        }
    }

    /// <summary>Return if the token may call the route.</summary>
    /// <exception cref="InsufficientScope">The token does not carry the route's scope, or the route is not in the map.</exception>
    public void Check(Claims claims, string method, string route)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(route);
        var upper = method.ToUpperInvariant();
        if (!_routes.TryGetValue((upper, route), out var required) || !claims.Scopes.Contains(required))
        {
            Log.Info(
                Category,
                "apiable.scope_refused reason={Reason} client={Client} method={Method} route={Route}",
                required is null ? "unmapped" : "scope",
                claims.Azp,
                upper,
                // A route that is not in the map can come from the request, such as an MCP tool
                // name, and stays out of the log.
                required is null ? "-" : route);
            throw new InsufficientScope(upper, route);
        }
    }
}
