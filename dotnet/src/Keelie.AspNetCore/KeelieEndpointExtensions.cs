using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Keelie.AspNetCore;

/// <summary>The per-route scope check, on a minimal API endpoint.</summary>
public static class KeelieEndpointExtensions
{
    /// <summary>
    /// Checks the scope of the endpoint it is on, against <paramref name="scopes"/>.
    /// </summary>
    /// <remarks>
    /// <code>
    /// var scopes = new ScopeMap(new Dictionary&lt;string, string&gt; { ["GET /v1/orders/{orderId}"] = "orders:read" });
    /// app.MapGet("/v1/orders/{orderId}", handler).RequireKeelieScope(scopes, metadata);
    /// </code>
    /// The route is the request's method and the endpoint's route template as you wrote it, the
    /// prefixes of its route groups included, such as <c>GET /v1/orders/{orderId}</c>. A path base
    /// set with <c>UsePathBase</c> is not part of it. A refused token gets <c>403</c> with
    /// <c>WWW-Authenticate: Bearer error="insufficient_scope"</c> and an empty body.
    /// <para>
    /// <see cref="KeelieApplicationBuilderExtensions.UseKeelieTokenGuard"/> must run first. Without
    /// its claims, the endpoint throws, so the mistake shows as a <c>500</c>. It is an endpoint
    /// filter, so it runs on minimal API endpoints. In an MVC action, call
    /// <see cref="ScopeMap.Check"/> yourself.
    /// </para>
    /// </remarks>
    public static TBuilder RequireKeelieScope<TBuilder>(this TBuilder builder, ScopeMap scopes, ProtectedResourceMetadata metadata)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(metadata);
        var refusal = metadata.Challenge("insufficient_scope");
        builder.AddEndpointFilter(async (invocation, next) =>
        {
            var context = invocation.HttpContext;
            var claims = context.GetKeelieClaims()
                ?? throw new InvalidOperationException("keelie: RequireKeelieScope needs UseKeelieTokenGuard to run before it");
            // An endpoint with no route template is in no map.
            var template = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText;
            var route = template is null ? "\0" : template.StartsWith('/') ? template : "/" + template;
            try
            {
                scopes.Check(claims, context.Request.Method, route);
            }
            catch (InsufficientScope)
            {
                await Guard.Respond(context, StatusCodes.Status403Forbidden, [new("WWW-Authenticate", refusal)]).ConfigureAwait(false);
                return Results.Empty;
            }
            return await next(invocation).ConfigureAwait(false);
        });
        return builder;
    }
}
