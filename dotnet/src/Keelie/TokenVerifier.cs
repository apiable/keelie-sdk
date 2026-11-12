using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Keelie;

/// <summary>Why a token was refused. For your log, never for the caller.</summary>
public enum RejectionReason
{
    /// <summary>The token does not parse, or a claim has the wrong form. Logged as <c>malformed</c>.</summary>
    Malformed,

    /// <summary>The token's <c>alg</c> is not RS256. Logged as <c>algorithm</c>.</summary>
    Algorithm,

    /// <summary>The token names no <c>kid</c>, or one that is not in the key set. Logged as <c>kid</c>.</summary>
    Kid,

    /// <summary>No key set is in hand, and the issuer could not be reached. Logged as <c>keys_unavailable</c>.</summary>
    KeysUnavailable,

    /// <summary>The signature does not verify. Logged as <c>signature</c>.</summary>
    Signature,

    /// <summary><c>exp</c> has passed. Logged as <c>expired</c>.</summary>
    Expired,

    /// <summary><c>nbf</c> or <c>iat</c> is in the future. Logged as <c>not_yet_valid</c>.</summary>
    NotYetValid,

    /// <summary><c>iss</c> is not your issuer. Logged as <c>issuer</c>.</summary>
    Issuer,

    /// <summary><c>aud</c> does not name your API. Logged as <c>audience</c>.</summary>
    Audience,

    /// <summary>A claim the SDK reads is missing or has the wrong type. Logged as <c>claims</c>.</summary>
    Claims,

    /// <summary><c>org_id</c> is another org's. Logged as <c>org</c>.</summary>
    Org,

    /// <summary><c>typ</c> is not <c>Bearer</c>. Logged as <c>typ</c>.</summary>
    Typ,
}

/// <summary>The token does not verify. <see cref="Reason"/> is for the log.</summary>
public sealed class TokenRejected : Exception
{
    /// <summary>A refusal for <paramref name="reason"/>.</summary>
    public TokenRejected(RejectionReason reason)
        : base(CodeOf(reason))
    {
        Reason = reason;
    }

    /// <summary>Why the token was refused.</summary>
    public RejectionReason Reason { get; }

    /// <summary>The reason as the log writes it, the same word in every SDK, such as <c>not_yet_valid</c>.</summary>
    public string ReasonCode => CodeOf(Reason);

    internal static string CodeOf(RejectionReason reason) => reason switch
    {
        RejectionReason.Malformed => "malformed",
        RejectionReason.Algorithm => "algorithm",
        RejectionReason.Kid => "kid",
        RejectionReason.KeysUnavailable => "keys_unavailable",
        RejectionReason.Signature => "signature",
        RejectionReason.Expired => "expired",
        RejectionReason.NotYetValid => "not_yet_valid",
        RejectionReason.Issuer => "issuer",
        RejectionReason.Audience => "audience",
        RejectionReason.Claims => "claims",
        RejectionReason.Org => "org",
        RejectionReason.Typ => "typ",
        _ => "malformed",
    };
}

/// <summary>The claims of a verified token that the SDK reads.</summary>
/// <param name="Azp">
/// The client the token was issued to: the credential. <c>sub</c> names the issuer's own
/// service-account user and is ignored. Report usage with it.
/// </param>
/// <param name="OrgId">Your org id.</param>
/// <param name="Scopes">The scopes of the token.</param>
/// <param name="Jti">The token id. Log it. Never log the token.</param>
/// <param name="ExpiresAt">
/// When the token expires, from <c>exp</c>, in UTC. While keelie is down, the Consumer is served
/// until then, and refused after.
/// </param>
/// <param name="ConsumerId">
/// On a token for a person, the Consumer whose credits the person uses: the <c>consumer_id</c>
/// claim. <see cref="Azp"/> is then the agent's client, which serves every Consumer.
/// <see langword="null"/> on a credential's token, which names its Consumer by <see cref="Azp"/>.
/// Pass it to <see cref="UsageReporter.Record"/> with <see cref="Azp"/>.
/// </param>
public sealed record Claims(
    string Azp,
    Guid OrgId,
    IReadOnlySet<string> Scopes,
    string? Jti,
    DateTimeOffset ExpiresAt,
    Guid? ConsumerId = null);

/// <summary>Options of <see cref="TokenVerifier"/>.</summary>
public sealed class TokenVerifierOptions
{
    /// <summary>The key set. One made from the issuer unless you give another, such as in a test.</summary>
    public SigningKeys? Keys { get; init; }

    /// <summary>The clock skew a token is forgiven. 30 seconds.</summary>
    public TimeSpan Leeway { get; init; } = TokenVerifier.DefaultLeeway;

    /// <summary>The clock the times of a token are checked against. <see cref="TimeProvider.System"/> unless you give another.</summary>
    public TimeProvider? TimeProvider { get; init; }
}

/// <summary>
/// Verifies the tokens of one issuer, for one audience and one org, inside your own process.
/// </summary>
/// <remarks>
/// The SDK never asks Apiable whether a token is good. It checks the signature against the
/// issuer's key set (see <see cref="SigningKeys"/>) and the claims against what you configured. The
/// checks run in this order, and the first that fails refuses the token:
/// <list type="number">
/// <item>The token parses, its <c>alg</c> is <c>RS256</c> and it names a <c>kid</c>. A token that
/// says <c>none</c> or <c>HS256</c> is refused before any key is fetched.</item>
/// <item>The key with that <c>kid</c> is in the issuer's key set.</item>
/// <item>The signature, <c>exp</c> (required), <c>nbf</c>, <c>iat</c>, <c>iss</c> and <c>aud</c>.</item>
/// <item><c>azp</c> names the client, and <c>org_id</c> is your own org id.</item>
/// <item><c>typ</c> is <c>Bearer</c>. An ID token is signed with the same key.</item>
/// </list>
/// <para>
/// The issuer is your own realm: the <c>issuer</c> member of your org in keelie. Each Provider has
/// its own realm, with its own <c>iss</c> and its own key set, so a token of another Provider fails
/// at step 2 or 3. The <c>org_id</c> check stays as a second line: a Provider whose Consumers keelie
/// made before it had a realm shares one issuer and one key set with others, and there
/// <c>org_id</c> tells them apart.
/// </para>
/// <para>
/// Every refusal throws <see cref="TokenRejected"/>. Its reason is for your log, not for the
/// caller: a caller must not learn "expired" from "wrong key".
/// </para>
/// </remarks>
public sealed class TokenVerifier
{
    /// <summary>The clock skew a token is forgiven.</summary>
    public static readonly TimeSpan DefaultLeeway = TimeSpan.FromSeconds(30);

    private const string TokenType = "Bearer";
    private const string Category = "Keelie.TokenVerifier";
    private static readonly JsonDocumentOptions JsonOptions = new() { MaxDepth = 1000 };

    private readonly string _issuer;
    private readonly Guid _orgId;
    private readonly SigningKeys _keys;
    private readonly double _leeway;
    private readonly TimeProvider _time;

    /// <summary>
    /// A verifier for <paramref name="issuer"/>, the <c>issuer</c> of your org in keelie;
    /// <paramref name="audience"/>, your API's <c>resource</c> in keelie, exactly; and
    /// <paramref name="orgId"/>, your org's <c>id</c>.
    /// </summary>
    public TokenVerifier(string issuer, string audience, Guid orgId, TokenVerifierOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(audience);
        _issuer = issuer;
        Audience = audience;
        _orgId = orgId;
        _keys = options?.Keys ?? new SigningKeys(issuer);
        _leeway = (options?.Leeway ?? DefaultLeeway).TotalSeconds;
        _time = options?.TimeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// A verifier whose <paramref name="orgId"/> is given as text, such as from the environment.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="orgId"/> is not a UUID.</exception>
    public TokenVerifier(string issuer, string audience, string orgId, TokenVerifierOptions? options = null)
        : this(issuer, audience, Compat.ParseUuid(orgId) ?? throw new ArgumentException($"orgId is not a UUID: {JsonSerializer.Serialize(orgId)}", nameof(orgId)), options)
    {
    }

    /// <summary>The <c>aud</c> every token must carry: your server's <c>resource</c> in keelie.</summary>
    public string Audience { get; }

    /// <summary>
    /// What the SDK knows of the issuer, from its last fetch of the key set.
    /// </summary>
    /// <remarks>
    /// It makes no network call, and the SDK does not poll. The SDK fetches only on a cold start and
    /// for a key it does not know. So while the keys in hand verify every token, an outage of the
    /// issuer leaves the status as it is.
    /// </remarks>
    public IssuerStatus Status => _keys.Status;

    /// <summary>The claims of the token.</summary>
    /// <exception cref="TokenRejected">The token does not verify, with the reason.</exception>
    public async Task<Claims> VerifyAsync(string token)
    {
        try
        {
            return await VerifyCoreAsync(token).ConfigureAwait(false);
        }
        catch (TokenRejected rejected)
        {
            Log.Info(Category, "apiable.token_rejected reason={Reason}", rejected.ReasonCode);
            throw;
        }
    }

    private async Task<Claims> VerifyCoreAsync(string? token)
    {
        // 1. It parses, alg is RS256, and it names a kid. The checks of the JWT library the Python
        // SDK uses, in its order.
        var parts = Jws.Load(token) ?? throw new TokenRejected(RejectionReason.Malformed);
        if (!parts.Header.TryGetValue("alg", out var alg)
            || alg.ValueKind != JsonValueKind.String
            || alg.GetString() != SigningKeys.Algorithm)
        {
            throw new TokenRejected(RejectionReason.Algorithm);
        }
        if (!parts.Header.TryGetValue("kid", out var kidElement) || kidElement.GetString() is not { Length: > 0 } kid)
        {
            throw new TokenRejected(RejectionReason.Kid);
        }

        // 2. The key with that kid is in the key set.
        RSAParameters key;
        try
        {
            key = await _keys.GetKeyAsync(kid).ConfigureAwait(false);
        }
        catch (UnknownKey)
        {
            throw new TokenRejected(RejectionReason.Kid);
        }
        catch (KeysUnavailable)
        {
            throw new TokenRejected(RejectionReason.KeysUnavailable);
        }

        // 3. The signature, then the registered claims.
        if (parts.DetachedPayload)
        {
            throw new TokenRejected(RejectionReason.Malformed);
        }
        bool verified;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(key);
            verified = rsa.VerifyData(parts.SigningInput, parts.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            verified = false;
        }
        if (!verified)
        {
            throw new TokenRejected(RejectionReason.Signature);
        }

        using var document = ParsePayload(parts.Payload);
        var payload = Jws.Members(document.RootElement);
        ValidateRegistered(payload);

        // 4. azp names the client, and org_id is your org id.
        var azp = payload.TryGetValue("azp", out var azpElement) ? azpElement : (JsonElement?)null;
        var scope = payload.TryGetValue("scope", out var scopeElement) ? scopeElement : (JsonElement?)null;
        var jti = payload.TryGetValue("jti", out var jtiElement) ? jtiElement : (JsonElement?)null;
        var orgId = payload.TryGetValue("org_id", out var orgElement) && orgElement.ValueKind == JsonValueKind.String
            ? Compat.ParseUuid(orgElement.GetString())
            : null;
        if (orgId is null)
        {
            throw new TokenRejected(RejectionReason.Claims);
        }
        if (azp is not { ValueKind: JsonValueKind.String } || azp.Value.GetString()!.Length == 0
            || (scope is not null && scope.Value.ValueKind != JsonValueKind.String)
            || (jti is not null && jti.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Null)))
        {
            throw new TokenRejected(RejectionReason.Claims);
        }
        if (orgId.Value != _orgId)
        {
            throw new TokenRejected(RejectionReason.Org);
        }

        // 5. typ is Bearer.
        if (!payload.TryGetValue("typ", out var typ) || typ.ValueKind != JsonValueKind.String || typ.GetString() != TokenType)
        {
            throw new TokenRejected(RejectionReason.Typ);
        }

        var expiresAt = ExpiresAt(payload["exp"]) ?? throw new TokenRejected(RejectionReason.Claims);
        Guid? consumerId = null;
        if (payload.TryGetValue("consumer_id", out var consumer) && consumer.ValueKind != JsonValueKind.Null)
        {
            consumerId = consumer.ValueKind == JsonValueKind.String ? Compat.ParseUuid(consumer.GetString()) : null;
            if (consumerId is null)
            {
                throw new TokenRejected(RejectionReason.Claims);
            }
        }
        var scopes = scope is null ? string.Empty : scope.Value.GetString()!;
        return new Claims(
            azp.Value.GetString()!,
            orgId.Value,
            Compat.SplitSpace(scopes).ToFrozenSet(StringComparer.Ordinal),
            jti is { ValueKind: JsonValueKind.String } ? jti.Value.GetString() : null,
            expiresAt,
            consumerId);
    }

    private static JsonDocument ParsePayload(byte[] payload)
    {
        try
        {
            var document = JsonDocument.Parse(payload, JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                document.Dispose();
                throw new TokenRejected(RejectionReason.Malformed);
            }
            return document;
        }
        catch (JsonException)
        {
            throw new TokenRejected(RejectionReason.Malformed);
        }
    }

    /// <summary>The checks of the JWT library the Python SDK uses, in its order, with its outcomes.</summary>
    private void ValidateRegistered(Dictionary<string, JsonElement> payload)
    {
        // exp is required: missing or null.
        if (!payload.TryGetValue("exp", out var exp) || exp.ValueKind == JsonValueKind.Null)
        {
            throw new TokenRejected(RejectionReason.Claims);
        }
        var now = _time.GetUtcNow().ToUnixTimeMilliseconds() / 1000.0;
        if (payload.TryGetValue("iat", out var iat))
        {
            if (!Compat.TryPythonInt(iat, out var issued) || issued > now + _leeway)
            {
                throw new TokenRejected(RejectionReason.NotYetValid);
            }
        }
        if (payload.TryGetValue("nbf", out var nbf))
        {
            if (!Compat.TryPythonInt(nbf, out var notBefore))
            {
                throw new TokenRejected(RejectionReason.Malformed);
            }
            if (notBefore > now + _leeway)
            {
                throw new TokenRejected(RejectionReason.NotYetValid);
            }
        }
        if (!Compat.TryPythonInt(exp, out var expires))
        {
            throw new TokenRejected(RejectionReason.Malformed);
        }
        if (expires <= now - _leeway)
        {
            throw new TokenRejected(RejectionReason.Expired);
        }

        if (!payload.TryGetValue("iss", out var iss))
        {
            throw new TokenRejected(RejectionReason.Claims);
        }
        if (iss.ValueKind != JsonValueKind.String || iss.GetString() != _issuer)
        {
            throw new TokenRejected(RejectionReason.Issuer);
        }

        if (!payload.TryGetValue("aud", out var aud) || IsFalsy(aud))
        {
            throw new TokenRejected(RejectionReason.Audience);
        }
        var audiences = new List<string>();
        if (aud.ValueKind == JsonValueKind.String)
        {
            audiences.Add(aud.GetString()!);
        }
        else if (aud.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in aud.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    throw new TokenRejected(RejectionReason.Audience);
                }
                audiences.Add(item.GetString()!);
            }
        }
        else
        {
            throw new TokenRejected(RejectionReason.Audience);
        }
        if (!audiences.Contains(Audience, StringComparer.Ordinal))
        {
            throw new TokenRejected(RejectionReason.Audience);
        }

        // sub and jti, when present, are strings.
        if ((payload.TryGetValue("sub", out var sub) && sub.ValueKind != JsonValueKind.String)
            || (payload.TryGetValue("jti", out var jti) && jti.ValueKind != JsonValueKind.String))
        {
            throw new TokenRejected(RejectionReason.Malformed);
        }
    }

    /// <summary>Python's truth test on a JSON value: null, false, 0, "", [] and {} are false.</summary>
    private static bool IsFalsy(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.False or JsonValueKind.Undefined => true,
        JsonValueKind.Number => value.TryGetDouble(out var number) && number == 0,
        JsonValueKind.String => value.GetString()!.Length == 0,
        JsonValueKind.Array => value.GetArrayLength() == 0,
        JsonValueKind.Object => !value.EnumerateObject().Any(),
        _ => false,
    };

    /// <summary><c>exp</c> as a time, as Python's <c>datetime.fromtimestamp</c> reads it: a number, in range.</summary>
    private static DateTimeOffset? ExpiresAt(JsonElement exp)
    {
        if (exp.ValueKind != JsonValueKind.Number || !exp.TryGetDouble(out var seconds) || !double.IsFinite(seconds))
        {
            return null;
        }
        var microseconds = Math.Round(seconds * 1_000_000, MidpointRounding.ToEven);
        var min = (DateTimeOffset.MinValue - DateTimeOffset.UnixEpoch).Ticks / 10.0;
        var max = (DateTimeOffset.MaxValue - DateTimeOffset.UnixEpoch).Ticks / 10.0;
        if (microseconds < min || microseconds > max)
        {
            return null;
        }
        return DateTimeOffset.UnixEpoch.AddTicks((long)microseconds * 10);
    }
}

/// <summary>A compact JWS taken apart, by the rules of the JWT library the Python SDK uses.</summary>
internal sealed class Jws
{
    private static readonly JsonDocumentOptions JsonOptions = new() { MaxDepth = 1000 };

    private Jws(Dictionary<string, JsonElement> header, byte[] signingInput, byte[] payload, byte[] signature, bool detached)
    {
        Header = header;
        SigningInput = signingInput;
        Payload = payload;
        Signature = signature;
        DetachedPayload = detached;
    }

    internal Dictionary<string, JsonElement> Header { get; }

    internal byte[] SigningInput { get; }

    internal byte[] Payload { get; }

    internal byte[] Signature { get; }

    /// <summary>The header says <c>"b64": false</c>. The SDK has no detached payload, so the token is refused after the key.</summary>
    internal bool DetachedPayload { get; }

    /// <summary>The parts of <paramref name="token"/>, or <see langword="null"/> if it does not parse.</summary>
    internal static Jws? Load(string? token)
    {
        if (token is null)
        {
            return null;
        }
        var bytes = Encoding.UTF8.GetBytes(token);
        var last = Array.LastIndexOf(bytes, (byte)'.');
        if (last < 0)
        {
            return null;
        }
        var first = Array.IndexOf(bytes, (byte)'.', 0, last);
        if (first < 0)
        {
            return null;
        }
        var headerBytes = DecodeSegment(bytes.AsSpan(0, first));
        if (headerBytes is null)
        {
            return null;
        }
        Dictionary<string, JsonElement> header;
        try
        {
            using var document = JsonDocument.Parse(headerBytes, JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            header = Members(document.RootElement.Clone());
        }
        catch (JsonException)
        {
            return null;
        }

        var payloadSegment = bytes.AsSpan(first + 1, last - first - 1);
        var detached = header.TryGetValue("b64", out var b64) && b64.ValueKind == JsonValueKind.False;
        byte[]? payload;
        if (detached)
        {
            if (payloadSegment.Length != 0)
            {
                return null;
            }
            payload = [];
        }
        else
        {
            payload = DecodeSegment(payloadSegment);
        }
        var signature = DecodeSegment(bytes.AsSpan(last + 1));
        if (payload is null || signature is null)
        {
            return null;
        }

        // The kid is a string when present, and "crit" names only extensions the library knows.
        if (header.TryGetValue("kid", out var kid) && kid.ValueKind != JsonValueKind.String)
        {
            return null;
        }
        if (header.TryGetValue("crit", out var crit))
        {
            if (crit.ValueKind != JsonValueKind.Array || crit.GetArrayLength() == 0)
            {
                return null;
            }
            foreach (var extension in crit.EnumerateArray())
            {
                if (extension.ValueKind != JsonValueKind.String || extension.GetString() != "b64" || !header.ContainsKey("b64"))
                {
                    return null;
                }
            }
        }
        return new Jws(header, bytes.AsSpan(0, last).ToArray(), payload, signature, detached);
    }

    /// <summary>The members of a JSON object. A name given twice keeps its last value, as Python's parser does.</summary>
    internal static Dictionary<string, JsonElement> Members(JsonElement element)
    {
        var members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            members[property.Name] = property.Value;
        }
        return members;
    }

    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>
    /// One base64url segment, strictly: at most two '=' and only on a whole quantum, only the
    /// alphabet, and only the one encoding of the bytes (no stray bits).
    /// </summary>
    private static byte[]? DecodeSegment(ReadOnlySpan<byte> segment)
    {
        var padding = 0;
        var stripped = segment;
        while (stripped.Length > 0 && stripped[^1] == (byte)'=')
        {
            stripped = stripped[..^1];
            padding++;
            if (padding > 2)
            {
                return null;
            }
        }
        if (padding > 0 && segment.Length % 4 != 0)
        {
            return null;
        }
        if (stripped.Length % 4 == 1)
        {
            return null;
        }
        foreach (var b in stripped)
        {
            if (Alphabet.IndexOf((char)b) < 0)
            {
                return null;
            }
        }
        var text = Encoding.ASCII.GetString(stripped).Replace('-', '+').Replace('_', '/');
        text = text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '=');
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            return null;
        }
        var again = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return again == Encoding.ASCII.GetString(stripped) ? decoded : null;
    }
}
