# frozen_string_literal: true

require_relative "support"

class KeysTest < Minitest::Test
  include Support

  DISCOVERY = "#{ISSUER}/.well-known/openid-configuration".freeze

  def setup
    @pair = key_pair("key-1")
    @issuer = FakeIssuer.new(@pair)
    @clock = Clock.new
    @keys = Keelie::SigningKeys.new("#{ISSUER}/", http: @issuer, clock: @clock)
  end

  def test_fetches_the_key_set_once_for_every_thread_that_finds_it_cold
    @issuer.delay = 0.05
    Array.new(20) { Thread.new { @keys.key("key-1") } }.each(&:join)
    assert_equal [DISCOVERY, JWKS_URI], @issuer.requests
    assert_equal :connected, @keys.status
  end

  def test_keeps_the_jwks_uri_and_fetches_an_unknown_kid_once_a_minute_at_most
    @keys.key("key-1")
    assert_raises(Keelie::UnknownKey) { @keys.key("made-up-1") }
    @issuer.requests.clear
    @clock.now += 30
    assert_raises(Keelie::UnknownKey) { @keys.key("made-up-2") }
    assert_raises(Keelie::UnknownKey) { @keys.key("made-up-3") }
    assert_empty @issuer.requests
    @clock.now += 31
    assert_raises(Keelie::UnknownKey) { @keys.key("made-up-4") }
    assert_equal [JWKS_URI], @issuer.requests
  end

  def test_picks_up_a_rotated_key_on_its_first_token
    @keys.key("key-1")
    @issuer.keys = [@pair.jwk, key_pair("key-2", index: 1).jwk]
    @clock.now += 60
    @keys.key("key-2")
    @keys.key("key-1")
  end

  def test_refuses_a_discovery_document_of_another_issuer
    ["https://issuer.example.com/realms/other", "#{ISSUER}x", "", nil, 7].each do |says|
      issuer = FakeIssuer.new(@pair)
      issuer.discovery_issuer = says
      keys = Keelie::SigningKeys.new(ISSUER, http: issuer, clock: @clock)
      capture_log { assert_raises(Keelie::KeysUnavailable) { keys.key("key-1") } }
      assert_equal [DISCOVERY], issuer.requests, says.inspect
      assert_equal :offline, keys.status
    end
  end

  def test_takes_a_trailing_slash_on_either_side_as_the_same_issuer
    @issuer.discovery_issuer = "#{ISSUER}/"
    @keys.key("key-1")
  end

  def test_caches_nothing_on_a_cold_failure_so_the_next_caller_tries_again
    @issuer.down = true
    capture_log { assert_raises(Keelie::KeysUnavailable) { @keys.key("key-1") } }
    @issuer.down = false
    @keys.key("key-1")
    assert_equal :connected, @keys.status
  end

  def test_goes_on_verifying_with_the_keys_in_hand_when_a_refresh_fails
    @keys.key("key-1")
    @issuer.down = true
    @clock.now += 60
    capture_log do |lines|
      assert_raises(Keelie::UnknownKey) { @keys.key("key-2") }
      assert_includes lines, "apiable.keys_not_refreshed: Errno::ECONNREFUSED"
    end
    assert_equal :degraded, @keys.status
    @keys.key("key-1")
    # A failed fetch also waits an interval before the next.
    @issuer.requests.clear
    assert_raises(Keelie::UnknownKey) { @keys.key("key-3") }
    assert_empty @issuer.requests
    @issuer.down = false
    @clock.now += 60
    assert_raises(Keelie::UnknownKey) { @keys.key("key-4") }
    assert_equal :connected, @keys.status
  end

  def test_refuses_an_answer_that_is_not_a_key_set
    [[500, {}], [200, { "nope" => [] }], [200, { "keys" => "x" }], [200, []]].each do |status, body|
      issuer = FakeIssuer.new(@pair)
      issuer.define_singleton_method(:call) do |method, url, **options|
        url == JWKS_URI ? json(status, body) : super(method, url, **options)
      end
      keys = Keelie::SigningKeys.new(ISSUER, http: issuer)
      capture_log { assert_raises(Keelie::KeysUnavailable) { keys.key("key-1") } }
    end
  end

  def test_loads_only_rsa_signing_keys_for_rs256_and_only_their_public_part
    other = key_pair("key-2", index: 1)
    small = key_pair("small", bits: 1024)
    @issuer.keys = [
      other.jwk.merge("kid" => "enc", "use" => "enc"),
      other.jwk.merge("kid" => "ps", "alg" => "PS256"),
      { "kty" => "EC", "kid" => "ec", "crv" => "P-256", "x" => "x", "y" => "y" },
      { "kty" => "RSA", "kid" => "broken", "n" => "!", "e" => "AQAB" },
      { "kty" => "RSA", "kid" => "no-n", "e" => "AQAB" },
      other.jwk.merge("kid" => "even-e", "e" => b64("\x02")),
      small.jwk,
      other.jwk.merge("kid" => "no-use").except("use", "alg"),
      other.jwk.merge("kid" => "null-use", "use" => nil, "alg" => nil),
      @pair.jwk.merge("d" => "a private member, published by mistake"),
      { "kid" => 7, "kty" => "RSA" },
      "not a key"
    ]
    capture_log do |lines|
      @keys.key("key-1")
      assert_includes lines, "apiable.key_skipped kid=small"
      assert_includes lines, "apiable.key_skipped kid=broken"
    end
    @keys.key("no-use")
    @keys.key("null-use")
    %w[enc ps ec broken no-n even-e small].each do |kid|
      assert_raises(Keelie::UnknownKey, kid) { @keys.key(kid) }
    end
    refute_predicate @keys.key("key-1"), :private?
  end

  def test_is_offline_until_the_first_token
    assert_equal :offline, @keys.status
  end
end
