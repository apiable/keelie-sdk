namespace Keelie.Tests;

public sealed class TokenTests
{
    private readonly FakeIssuer _issuer;
    private readonly TestKey _key;
    private readonly ManualClock _clock = new();
    private readonly TokenVerifier _verifier;

    public TokenTests()
    {
        (_issuer, _key) = StandardIssuer.Make();
        _verifier = _issuer.Verifier(_clock);
    }

    private async Task<RejectionReason> RejectedAsync(string token)
    {
        var rejected = await Assert.ThrowsAsync<TokenRejected>(() => _verifier.VerifyAsync(token));
        return rejected.Reason;
    }

    [Fact]
    public async Task A_valid_token_verifies_with_one_fetch_for_all_callers()
    {
        var token = Tokens.Sign(_key);

        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => _verifier.VerifyAsync(token)));

        Assert.Equal("client-1", results[0].Azp);
        Assert.Equal(Values.OrgId, results[0].OrgId);
        Assert.Equal(new[] { "orders:read", "orders:write" }, results[0].Scopes.Order());
        Assert.Equal("jti-1", results[0].Jti);
        Assert.Null(results[0].ConsumerId);
        Assert.Equal(1, _issuer.JwksFetches);
    }

    [Fact]
    public async Task A_rotated_key_is_picked_up_without_a_restart()
    {
        await _verifier.VerifyAsync(Tokens.Sign(_key));
        var newKey = new TestKey("sig-2");
        _issuer.Keys = [newKey.Jwk()];

        // Within the minute, an unknown kid is refused and costs the issuer nothing.
        Assert.Equal(RejectionReason.Kid, await RejectedAsync(Tokens.Sign(newKey)));
        Assert.Equal(1, _issuer.JwksFetches);

        _clock.Advance(60);
        var claims = await _verifier.VerifyAsync(Tokens.Sign(newKey));

        Assert.Equal("client-1", claims.Azp);
        Assert.Equal(2, _issuer.JwksFetches);
    }

    [Fact]
    public async Task An_unknown_kid_fetches_once_then_is_refused()
    {
        await _verifier.VerifyAsync(Tokens.Sign(_key));
        _clock.Advance(60);

        foreach (var kid in new[] { "made-up-1", "made-up-2", "made-up-3" })
        {
            Assert.Equal(RejectionReason.Kid, await RejectedAsync(Tokens.Sign(_key, kid: kid)));
        }

        Assert.Equal(2, _issuer.JwksFetches);
    }

    [Fact]
    public async Task A_cold_cache_refuses_when_the_issuer_is_down_and_retries_next_time()
    {
        _issuer.Down = true;
        Assert.Equal(RejectionReason.KeysUnavailable, await RejectedAsync(Tokens.Sign(_key)));

        _issuer.Down = false;
        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key));

        Assert.Equal("client-1", claims.Azp);
    }

    [Fact]
    public async Task A_warm_cache_keeps_verifying_when_the_issuer_is_down()
    {
        await _verifier.VerifyAsync(Tokens.Sign(_key));
        _issuer.Down = true;
        _clock.Advance(60);

        Assert.Equal(RejectionReason.Kid, await RejectedAsync(Tokens.Sign(_key, kid: "sig-2")));
        // The failed fetch also counts: the issuer is not asked again for a minute.
        _issuer.Down = false;
        await RejectedAsync(Tokens.Sign(_key, kid: "sig-2"));

        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key));
        Assert.Equal("client-1", claims.Azp);
        Assert.Equal(1, _issuer.JwksFetches);
    }

    public static TheoryData<string, string> FailedChecks()
    {
        // A name, read by the test, and the reason as the log writes it.
        return new TheoryData<string, string>
        {
            { "not-a-token", "malformed" },
            { "hs256", "algorithm" },
            { "none", "algorithm" },
            { "no kid", "kid" },
            { "empty kid", "kid" },
            { "kid not a string", "malformed" },
            { "encryption key", "kid" },
            { "other algorithm key", "kid" },
            { "other signer", "signature" },
            { "expired", "expired" },
            { "no exp", "claims" },
            { "exp null", "claims" },
            { "exp not a number", "malformed" },
            { "nbf in the future", "not_yet_valid" },
            { "iat in the future", "not_yet_valid" },
            { "iat not a number", "not_yet_valid" },
            { "nbf not a number", "malformed" },
            { "other issuer", "issuer" },
            { "no issuer", "claims" },
            { "issuer not a string", "issuer" },
            { "other audience", "audience" },
            { "no audience", "audience" },
            { "empty audience", "audience" },
            { "audience a number", "audience" },
            { "no azp", "claims" },
            { "empty azp", "claims" },
            { "org_id not a uuid", "claims" },
            { "org_id a number", "claims" },
            { "no org_id", "claims" },
            { "scope a list", "claims" },
            { "scope null", "claims" },
            { "jti a number", "malformed" },
            { "sub a number", "malformed" },
            { "other org", "org" },
            { "typ ID", "typ" },
            { "no typ", "typ" },
            { "consumer_id not a uuid", "claims" },
            { "consumer_id a number", "claims" },
            { "b64 false", "malformed" },
            { "unknown crit", "malformed" },
            { "four parts", "malformed" },
            { "padding junk", "malformed" },
            { "payload not an object", "malformed" },
        };
    }

    private string TokenFor(string name)
    {
        var now = Tokens.Now;
        return name switch
        {
            "not-a-token" => "not-a-token",
            "hs256" => Tokens.Hs256("sig-1"),
            "none" => Tokens.Unsigned(new() { ["alg"] = "none", ["kid"] = "sig-1" }),
            "no kid" => Tokens.Sign(_key, header: new() { ["kid"] = Tokens.Omit }),
            "empty kid" => Tokens.Sign(_key, kid: ""),
            "kid not a string" => Tokens.Sign(_key, header: new() { ["kid"] = 7 }),
            "encryption key" => Tokens.Sign(_key, kid: "enc-rs256"),
            "other algorithm key" => Tokens.Sign(_key, kid: "rs512"),
            "other signer" => Tokens.Sign(new TestKey("sig-1")),
            "expired" => Tokens.Sign(_key, new() { ["exp"] = now - 31 }),
            "no exp" => Tokens.Sign(_key, new() { ["exp"] = Tokens.Omit }),
            "exp null" => Tokens.Sign(_key, new() { ["exp"] = null }),
            "exp not a number" => Tokens.Sign(_key, new() { ["exp"] = "soon" }),
            "nbf in the future" => Tokens.Sign(_key, new() { ["nbf"] = now + 60 }),
            "iat in the future" => Tokens.Sign(_key, new() { ["iat"] = now + 60 }),
            "iat not a number" => Tokens.Sign(_key, new() { ["iat"] = "now" }),
            "nbf not a number" => Tokens.Sign(_key, new() { ["nbf"] = "now" }),
            "other issuer" => Tokens.Sign(_key, new() { ["iss"] = "https://other.example.test/realms/test" }),
            "no issuer" => Tokens.Sign(_key, new() { ["iss"] = Tokens.Omit }),
            "issuer not a string" => Tokens.Sign(_key, new() { ["iss"] = 7 }),
            "other audience" => Tokens.Sign(_key, new() { ["aud"] = "another-api" }),
            "no audience" => Tokens.Sign(_key, new() { ["aud"] = Tokens.Omit }),
            "empty audience" => Tokens.Sign(_key, new() { ["aud"] = Array.Empty<string>() }),
            "audience a number" => Tokens.Sign(_key, new() { ["aud"] = 7 }),
            "no azp" => Tokens.Sign(_key, new() { ["azp"] = Tokens.Omit }),
            "empty azp" => Tokens.Sign(_key, new() { ["azp"] = "" }),
            "org_id not a uuid" => Tokens.Sign(_key, new() { ["org_id"] = "not-a-uuid" }),
            "org_id a number" => Tokens.Sign(_key, new() { ["org_id"] = 42 }),
            "no org_id" => Tokens.Sign(_key, new() { ["org_id"] = Tokens.Omit }),
            "scope a list" => Tokens.Sign(_key, new() { ["scope"] = new[] { "orders:read" } }),
            "scope null" => Tokens.Sign(_key, new() { ["scope"] = null }),
            "jti a number" => Tokens.Sign(_key, new() { ["jti"] = 7 }),
            "sub a number" => Tokens.Sign(_key, new() { ["sub"] = 7 }),
            "other org" => Tokens.Sign(_key, new() { ["org_id"] = Guid.NewGuid().ToString() }),
            "typ ID" => Tokens.Sign(_key, new() { ["typ"] = "ID" }),
            "no typ" => Tokens.Sign(_key, new() { ["typ"] = Tokens.Omit }),
            "consumer_id not a uuid" => Tokens.Sign(_key, new() { ["consumer_id"] = "not-a-uuid" }),
            "consumer_id a number" => Tokens.Sign(_key, new() { ["consumer_id"] = 42 }),
            "b64 false" => Tokens.Sign(_key, header: new() { ["b64"] = false, ["crit"] = new[] { "b64" } }).Split('.') is var p ? $"{p[0]}..{p[2]}" : "",
            "unknown crit" => Tokens.Sign(_key, header: new() { ["crit"] = new[] { "exp" } }),
            "four parts" => Tokens.Sign(_key) + ".x",
            "padding junk" => Tokens.Sign(_key) + "===",
            "payload not an object" => Tokens.SignPayload(_key, new[] { 1 }),
            _ => throw new ArgumentException(name),
        };
    }

    [Theory]
    [MemberData(nameof(FailedChecks))]
    public async Task Each_failed_check_refuses_the_token(string name, string reason)
    {
        var rejected = await Assert.ThrowsAsync<TokenRejected>(() => _verifier.VerifyAsync(TokenFor(name)));

        Assert.Equal(reason, rejected.ReasonCode);
    }

    [Fact]
    public async Task A_token_within_the_leeway_verifies()
    {
        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key, new() { ["exp"] = Tokens.Now - 20 }));

        Assert.Equal("client-1", claims.Azp);
    }

    [Fact]
    public async Task A_wrong_algorithm_is_refused_before_any_fetch()
    {
        await RejectedAsync(Tokens.Hs256("sig-1"));
        await RejectedAsync(Tokens.Unsigned(new() { ["alg"] = "none", ["kid"] = "sig-1" }));
        await RejectedAsync(Tokens.Unsigned(new() { ["alg"] = "RS256" }));

        Assert.Empty(_issuer.Requests);
    }

    [Fact]
    public async Task A_key_with_no_use_and_no_alg_verifies()
    {
        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key, kid: "bare"));

        Assert.Equal("client-1", claims.Azp);
    }

    [Fact]
    public async Task An_audience_list_that_names_the_api_verifies()
    {
        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key, new() { ["aud"] = new[] { "https://other.example.test", Values.Audience } }));

        Assert.Equal("client-1", claims.Azp);
    }

    [Fact]
    public async Task A_key_under_2048_bits_is_skipped_and_a_private_member_is_never_loaded()
    {
        var small = new TestKey("small", 1024);
        var withPrivate = new TestKey("private");
        _issuer.Keys.Add(small.Jwk());
        _issuer.Keys.Add(withPrivate.Jwk(new() { ["d"] = "a private member, published by mistake" }));

        Assert.Equal(RejectionReason.Kid, await RejectedAsync(Tokens.Sign(small)));
        Assert.Equal("client-1", (await _verifier.VerifyAsync(Tokens.Sign(withPrivate))).Azp);
    }

    private const string RealmA = "https://issuer.example.test/realms/01890000-0000-7000-8000-00000000000a";
    private const string RealmB = "https://issuer.example.test/realms/01890000-0000-7000-8000-00000000000b";

    [Fact]
    public async Task A_token_of_another_realm_is_refused()
    {
        // Each Provider has its own realm. A verifier for realm B refuses a token of realm A, with
        // A's own key and with a key both realms hold, and still verifies its own.
        var keyA = new TestKey("sig-a");
        var keyB = new TestKey("sig-b");
        var realmA = new FakeIssuer(RealmA) { Keys = [keyA.Jwk()] };
        var realmB = new FakeIssuer(RealmB) { Keys = [keyB.Jwk(), new TestKeyAlias(keyA, "shared").Jwk()] };
        var verifierA = realmA.Verifier(_clock);
        var verifierB = realmB.Verifier(_clock);
        var tokenA = Tokens.Sign(keyA, new() { ["iss"] = RealmA });

        Assert.Equal(Values.OrgId, (await verifierA.VerifyAsync(tokenA)).OrgId);
        Assert.Equal(RejectionReason.Kid, (await Assert.ThrowsAsync<TokenRejected>(() => verifierB.VerifyAsync(tokenA))).Reason);
        var shared = Tokens.Sign(keyA, new() { ["iss"] = RealmA }, kid: "shared");
        Assert.Equal(RejectionReason.Issuer, (await Assert.ThrowsAsync<TokenRejected>(() => verifierB.VerifyAsync(shared))).Reason);
        Assert.Equal("client-1", (await verifierB.VerifyAsync(Tokens.Sign(keyB, new() { ["iss"] = RealmB }))).Azp);
    }

    [Theory]
    [InlineData(RealmB)]
    [InlineData("")]
    [InlineData(RealmA + "x")]
    public async Task A_discovery_document_of_another_issuer_fetches_no_key(string says)
    {
        // The discovery document must name the configured issuer (OpenID Connect Discovery 1.0,
        // section 4.3). Otherwise no key is fetched, and the token is refused.
        var key = new TestKey("sig-a");
        var realm = new FakeIssuer(RealmA, says) { Keys = [key.Jwk()] };

        var rejected = await Assert.ThrowsAsync<TokenRejected>(() => realm.Verifier(_clock).VerifyAsync(Tokens.Sign(key, new() { ["iss"] = RealmA })));

        Assert.Equal(RejectionReason.KeysUnavailable, rejected.Reason);
        Assert.Equal(0, realm.JwksFetches);
    }

    [Fact]
    public async Task A_trailing_slash_on_either_side_is_the_same_issuer()
    {
        var key = new TestKey("sig-a");
        var realm = new FakeIssuer(RealmA, RealmA + "/") { Keys = [key.Jwk()] };
        var keys = new SigningKeys(RealmA + "/", new SigningKeysOptions { HttpClient = new HttpClient(realm) });
        var verifier = new TokenVerifier(RealmA, Values.Audience, Values.OrgId, new TokenVerifierOptions { Keys = keys });

        var claims = await verifier.VerifyAsync(Tokens.Sign(key, new() { ["iss"] = RealmA }));

        Assert.Equal(Values.OrgId, claims.OrgId);
    }

    [Fact]
    public async Task The_status_is_offline_until_the_first_token_fetches_the_keys()
    {
        Assert.Equal(IssuerStatus.Offline, _verifier.Status);

        await _verifier.VerifyAsync(Tokens.Sign(_key));

        Assert.Equal(IssuerStatus.Connected, _verifier.Status);
    }

    [Fact]
    public async Task The_status_is_offline_while_the_issuer_is_down_and_no_key_is_in_hand()
    {
        _issuer.Down = true;
        await RejectedAsync(Tokens.Sign(_key));

        Assert.Equal(IssuerStatus.Offline, _verifier.Status);
    }

    [Fact]
    public async Task The_status_is_degraded_after_a_failed_refresh_and_connected_after_a_good_one()
    {
        await _verifier.VerifyAsync(Tokens.Sign(_key));
        _issuer.Down = true;
        _clock.Advance(60);
        await RejectedAsync(Tokens.Sign(_key, kid: "sig-2"));

        Assert.Equal(IssuerStatus.Degraded, _verifier.Status);

        _issuer.Down = false;
        _clock.Advance(60);
        await RejectedAsync(Tokens.Sign(_key, kid: "sig-2"));

        Assert.Equal(IssuerStatus.Connected, _verifier.Status);
    }

    [Fact]
    public async Task A_token_whose_exp_is_a_string_is_refused()
    {
        Assert.Equal(RejectionReason.Claims, await RejectedAsync(Tokens.Sign(_key, new() { ["exp"] = (Tokens.Now + 300).ToString(System.Globalization.CultureInfo.InvariantCulture) })));
    }

    [Fact]
    public async Task The_claims_say_when_the_token_expires()
    {
        var exp = Tokens.Now + 300;

        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key, new() { ["exp"] = exp }));

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(exp), claims.ExpiresAt);
        Assert.Equal(TimeSpan.Zero, claims.ExpiresAt.Offset);
    }

    [Fact]
    public async Task A_token_for_a_person_names_its_consumer()
    {
        var consumer = Guid.NewGuid();

        var person = await _verifier.VerifyAsync(Tokens.Sign(_key, new() { ["consumer_id"] = consumer.ToString().ToUpperInvariant() }));
        var credential = await _verifier.VerifyAsync(Tokens.Sign(_key));

        Assert.Equal(consumer, person.ConsumerId);
        Assert.Null(credential.ConsumerId);
    }

    [Fact]
    public async Task A_missing_scope_is_no_scope()
    {
        var claims = await _verifier.VerifyAsync(Tokens.Sign(_key, new() { ["scope"] = Tokens.Omit }));

        Assert.Empty(claims.Scopes);
    }

    [Fact]
    public void An_org_id_that_is_not_a_uuid_does_not_start()
    {
        Assert.Throws<ArgumentException>(() => new TokenVerifier(Values.Issuer, Values.Audience, "portal-labs"));
        // Python's rules: braces, "urn:uuid:" and any case are read.
        _ = new TokenVerifier(Values.Issuer, Values.Audience, "{" + Values.OrgId.ToString().ToUpperInvariant() + "}");
        _ = new TokenVerifier(Values.Issuer, Values.Audience, "urn:uuid:" + Values.OrgId);
    }
}
