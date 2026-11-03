# frozen_string_literal: true

require_relative "support"

class TokensTest < Minitest::Test
  include Support

  def setup
    @pair = key_pair("key-1")
    @issuer = FakeIssuer.new(@pair)
    @clock = Clock.new
    @verifier = Keelie::TokenVerifier.new(ISSUER, RESOURCE, ORG_ID,
                                          keys: Keelie::SigningKeys.new(ISSUER, http: @issuer, clock: @clock))
  end

  def assert_rejected(reason, token, verifier = @verifier)
    error = assert_raises(Keelie::TokenRejected) { verifier.verify(token) }
    assert_equal reason, error.reason, "expected #{reason} for #{token[0, 40]}..."
  end

  def test_returns_the_claims_of_a_good_token
    claims = @verifier.verify(sign(@pair))
    assert_equal "consumer-client", claims.azp
    assert_equal ORG_ID, claims.org_id
    assert_equal Set["orders:read", "profile"], claims.scopes
    assert_equal "token-1", claims.jti
    assert_nil claims.consumer_id
    assert_operator claims.expires_at, :>, Time.now
    assert_predicate claims, :frozen?
    assert_predicate claims.scopes, :frozen?
    assert claims.expires_at.utc?
  end

  def test_one_fetch_serves_every_thread_that_finds_the_cache_cold
    @issuer.delay = 0.05
    token = sign(@pair)
    results = Array.new(8) { Thread.new { @verifier.verify(token) } }.map(&:value)
    assert(results.all? { _1.azp == "consumer-client" })
    assert_equal 1, @issuer.jwks_fetches
  end

  def test_says_when_the_token_expires
    exp = Time.now.to_i + 300
    assert_equal Time.at(exp).utc, @verifier.verify(sign(@pair, "exp" => exp)).expires_at
  end

  def test_reads_consumer_id_in_its_canonical_form
    claims = @verifier.verify(sign(@pair, "consumer_id" => CONSUMER.upcase))
    assert_equal CONSUMER, claims.consumer_id
    assert_nil @verifier.verify(sign(@pair, "consumer_id" => nil)).consumer_id
  end

  def test_refuses_another_algorithm_before_any_key_is_fetched
    assert_rejected :algorithm, unsigned({ "alg" => "none", "kid" => "key-1" })
    assert_rejected :algorithm, unsigned({ "alg" => "HS256", "kid" => "key-1" })
    assert_rejected :algorithm, unsigned({ "kid" => "key-1" })
    assert_rejected :kid, unsigned({ "alg" => "RS256" })
    assert_rejected :kid, unsigned({ "alg" => "RS256", "kid" => "" })
    assert_empty @issuer.requests
  end

  def test_refuses_an_hs256_token_signed_with_a_shared_secret
    input = "#{b64(JSON.generate("alg" => "HS256", "kid" => "key-1"))}.#{b64(JSON.generate(claims))}"
    token = "#{input}.#{b64(OpenSSL::HMAC.digest("SHA256", "x" * 32, input))}"
    assert_rejected :algorithm, token
  end

  def test_refuses_what_does_not_parse
    ["not-a-token", "", "a.b", "a.b.c.d", "!!!!.e30.c2ln", "#{b64("[1]")}.#{b64("{}")}.c2ln", nil, 42].each do |bad|
      error = assert_raises(Keelie::TokenRejected) { @verifier.verify(bad) }
      assert_equal :malformed, error.reason, bad.inspect
    end
  end

  def test_refuses_a_header_pyjwt_refuses
    assert_rejected :malformed, unsigned({ "alg" => "RS256", "kid" => 7 })
    assert_rejected :malformed, unsigned({ "alg" => "RS256", "kid" => "key-1", "crit" => ["exp"] })
    assert_rejected :malformed, unsigned({ "alg" => "RS256", "kid" => "key-1", "crit" => [] })
    assert_rejected :malformed, sign(@pair, {}, "b64" => false)
    # A known critical extension, present, passes the header check.
    @verifier.verify(sign(@pair, {}, "crit" => ["b64"], "b64" => true))
  end

  def test_refuses_an_unknown_kid
    assert_rejected :kid, sign(key_pair("key-2", index: 1))
  end

  def test_refuses_a_signature_of_another_key_with_the_same_kid
    assert_rejected :signature, sign(key_pair("key-1", index: 1))
    token = sign(@pair)
    assert_rejected :signature, "#{token[0...token.rindex(".")]}.#{b64("short")}"
  end

  def test_refuses_a_payload_that_is_not_an_object
    header = b64(JSON.generate("alg" => "RS256", "kid" => "key-1"))
    ["[1]", "not json"].each do |payload|
      input = "#{header}.#{b64(payload)}"
      token = "#{input}.#{b64(@pair.private_key.sign(OpenSSL::Digest.new("SHA256"), input))}"
      assert_rejected :malformed, token
    end
  end

  def test_checks_the_times
    now = Time.now.to_i
    assert_rejected :expired, sign(@pair, "exp" => now - 31)
    @verifier.verify(sign(@pair, "exp" => now - 20)) # inside the leeway
    assert_rejected :not_yet_valid, sign(@pair, "nbf" => now + 60)
    assert_rejected :not_yet_valid, sign(@pair, "iat" => now + 60)
    assert_rejected :not_yet_valid, sign(@pair, "iat" => "soon")
    assert_rejected :claims, sign(@pair, "exp" => ABSENT)
    assert_rejected :claims, sign(@pair, "exp" => nil)
    assert_rejected :malformed, sign(@pair, "exp" => "soon")
    assert_rejected :malformed, sign(@pair, "exp" => [now + 300])
    assert_rejected :malformed, sign(@pair, "nbf" => "soon")
    # Python's int() reads the text, then the date cannot be made from it.
    assert_rejected :claims, sign(@pair, "exp" => (now + 300).to_s)
    assert_rejected :claims, sign(@pair, "exp" => 300_000_000_000)
    @verifier.verify(sign(@pair, "exp" => now + 300.5, "iat" => now.to_f, "nbf" => now - 1))
  end

  def test_checks_the_issuer_and_the_audience
    assert_rejected :issuer, sign(@pair, "iss" => "https://issuer.example.com/realms/other")
    assert_rejected :issuer, sign(@pair, "iss" => 7)
    assert_rejected :claims, sign(@pair, "iss" => ABSENT)
    assert_rejected :audience, sign(@pair, "aud" => "https://api.example.com/v2")
    assert_rejected :audience, sign(@pair, "aud" => ABSENT)
    assert_rejected :audience, sign(@pair, "aud" => "")
    assert_rejected :audience, sign(@pair, "aud" => [])
    assert_rejected :audience, sign(@pair, "aud" => [RESOURCE, 7])
    assert_rejected :audience, sign(@pair, "aud" => { "a" => RESOURCE })
    @verifier.verify(sign(@pair, "aud" => ["https://other.example.com", RESOURCE]))
  end

  def test_checks_the_claims_keelie_writes
    assert_rejected :org, sign(@pair, "org_id" => OTHER_ORG)
    assert_rejected :claims, sign(@pair, "org_id" => "nope")
    assert_rejected :claims, sign(@pair, "org_id" => 7)
    assert_rejected :claims, sign(@pair, "org_id" => ABSENT)
    assert_rejected :claims, sign(@pair, "azp" => ABSENT)
    assert_rejected :claims, sign(@pair, "azp" => "")
    assert_rejected :claims, sign(@pair, "scope" => ["orders:read"])
    assert_rejected :claims, sign(@pair, "scope" => nil)
    assert_rejected :typ, sign(@pair, "typ" => "ID")
    assert_rejected :typ, sign(@pair, "typ" => ABSENT)
    assert_rejected :claims, sign(@pair, "consumer_id" => "nope")
    assert_rejected :claims, sign(@pair, "consumer_id" => 42)
    # PyJWT refuses a jti or a sub that is not a string before the SDK reads the claims.
    assert_rejected :malformed, sign(@pair, "jti" => 7)
    assert_rejected :malformed, sign(@pair, "jti" => nil)
    assert_rejected :malformed, sign(@pair, "sub" => 7)
  end

  def test_reads_the_scope_claim_as_python_splits_it
    assert_empty @verifier.verify(sign(@pair, "scope" => ABSENT)).scopes
    assert_equal Set["a", "b", "c"], @verifier.verify(sign(@pair, "scope" => " a\tb\u00a0c ")).scopes
  end

  def test_a_rotated_key_is_picked_up_without_a_restart
    @verifier.verify(sign(@pair))
    rotated = key_pair("key-2", index: 1)
    @issuer.keys = [rotated.jwk]
    # Within the minute, an unknown kid is refused and costs the issuer nothing.
    assert_rejected :kid, sign(rotated)
    assert_equal 1, @issuer.jwks_fetches
    @clock.now += 60
    assert_equal "consumer-client", @verifier.verify(sign(rotated)).azp
    assert_equal 2, @issuer.jwks_fetches
  end

  def test_refuses_every_token_while_the_issuer_cannot_be_reached_and_tries_again
    @issuer.down = true
    capture_log do |lines|
      assert_rejected :keys_unavailable, sign(@pair)
      assert_includes lines, "apiable.keys_unavailable: Errno::ECONNREFUSED"
      assert_includes lines, "apiable.token_rejected reason=keys_unavailable"
    end
    assert_equal :offline, @verifier.status
    @issuer.down = false
    @verifier.verify(sign(@pair))
    assert_equal :connected, @verifier.status
  end

  def test_the_status_is_degraded_after_a_failed_refresh_and_connected_after_a_good_one
    assert_equal :offline, @verifier.status
    @verifier.verify(sign(@pair))
    @issuer.down = true
    @clock.now += 60
    capture_log { assert_rejected :kid, sign(@pair, {}, "kid" => "key-2") }
    assert_equal :degraded, @verifier.status
    @verifier.verify(sign(@pair)) # the keys in hand go on verifying
    @issuer.down = false
    @clock.now += 60
    assert_rejected :kid, sign(@pair, {}, "kid" => "key-2")
    assert_equal :connected, @verifier.status
  end

  def test_refuses_a_token_of_another_realm
    realm_a = "https://issuer.example.com/realms/01890000-0000-7000-8000-00000000000a"
    realm_b = "https://issuer.example.com/realms/01890000-0000-7000-8000-00000000000b"
    pair_a = key_pair("sig-a")
    pair_b = key_pair("sig-b", index: 1)
    issuer_b = FakeIssuer.new(pair_b, issuer: realm_b)
    issuer_b.keys = [pair_b.jwk, key_pair("shared").jwk]
    verifier_b = Keelie::TokenVerifier.new(realm_b, RESOURCE, ORG_ID,
                                           keys: Keelie::SigningKeys.new(realm_b, http: issuer_b, clock: @clock))
    assert_rejected :kid, sign(pair_a, "iss" => realm_a), verifier_b
    assert_rejected :issuer, sign(key_pair("shared"), "iss" => realm_a), verifier_b
    assert verifier_b.verify(sign(pair_b, "iss" => realm_b)).azp
  end

  def test_does_not_start_with_an_org_id_that_is_not_a_uuid
    assert_raises(ArgumentError) { Keelie::TokenVerifier.new(ISSUER, RESOURCE, "portal-labs") }
    assert_equal RESOURCE, Keelie::TokenVerifier.new(ISSUER, RESOURCE, "{#{ORG_ID.upcase}}").audience
  end
end
