using Microsoft.AspNetCore.Http;

namespace Keelie.AspNetCore;

/// <summary>The claims a Keelie guard put on the request.</summary>
public static class KeelieHttpContextExtensions
{
    /// <summary>
    /// The claims of the request's token, set by <see cref="KeelieApplicationBuilderExtensions.UseKeelieTokenGuard"/>
    /// or <see cref="KeelieApplicationBuilderExtensions.UseKeelieMcpGuard"/>. <see langword="null"/> on a
    /// request the guard did not check, such as one outside your address.
    /// </summary>
    public static Claims? GetKeelieClaims(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Features.Get<KeelieClaimsFeature>()?.Claims;
    }
}
