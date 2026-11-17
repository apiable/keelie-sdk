# frozen_string_literal: true

require_relative "support"

class ScopesDiscoveryTest < Minitest::Test
  include Support

  def claims_with(*scopes)
    Keelie::Claims.new(azp: "client", org_id: ORG_ID, scopes: Set.new(scopes).freeze, jti: nil,
                       expires_at: Time.now.utc, consumer_id: nil)
  end

  def scopes
    Keelie::ScopeMap.new("GET /orders/:order_id" => "orders:read", "post /orders" => "orders:write",
                         %w[DELETE /orders/:order_id] => "orders:write")
  end

  def test_passes_a_token_with_the_routes_scope
    scopes.check(claims_with("orders:read"), "get", "/orders/:order_id")
    scopes.check(claims_with("orders:write"), "POST", "/orders")
    scopes.check(claims_with("orders:write"), "DELETE", "/orders/:order_id")
  end

  def test_matches_a_scope_and_a_route_only_to_themselves
    [
      [%w[orders], "GET", "/orders/:order_id"],
      [%w[orders:read:all], "GET", "/orders/:order_id"],
      [%w[orders:read], "GET", "/orders/:order_id/items"],
      [%w[orders:read], "GET", "/orders/:id"],
      [%w[orders:read], "HEAD", "/orders/:order_id"],
      [%w[orders:read], "GET", "/unmapped"]
    ].each do |granted, method, route|
      assert_raises(Keelie::InsufficientScope) { scopes.check(claims_with(*granted), method, route) }
    end
  end

  def test_logs_a_refusal_without_a_route_that_is_not_in_the_map
    capture_log do |lines|
      assert_raises(Keelie::InsufficientScope) { scopes.check(claims_with, "GET", "/orders/:order_id") }
      assert_raises(Keelie::InsufficientScope) { scopes.check(claims_with, "GET", "/secret-tool-name") }
      assert_equal ["apiable.scope_refused reason=scope client=client method=GET route=/orders/:order_id",
                    "apiable.scope_refused reason=unmapped client=client method=GET route=-"], lines
    end
  end

  def test_refuses_a_map_that_is_not_one_scope_a_route
    [{ "GET /a" => "two scopes" }, { "GET /a" => "" }, { "GET /a" => "a\u00a0b" }, { "GET /a" => :s },
     { "/a" => "s" }, { "GET " => "s" }, { " /a" => "s" }, { %w[GET] => "s" },
     { "GET /a" => "s", "get /a" => "t" }].each do |routes|
      assert_raises(ArgumentError, routes.inspect) { Keelie::ScopeMap.new(routes) }
    end
  end

  def test_serves_the_metadata_between_the_host_and_the_path
    metadata = Keelie::ProtectedResourceMetadata.new("https://api.example.com/v1", ISSUER,
                                                     scopes_supported: ["orders:read"])
    assert_equal "/.well-known/oauth-protected-resource/v1", metadata.path
    assert_equal "https://api.example.com/.well-known/oauth-protected-resource/v1", metadata.url
    assert_equal '{"resource":"https://api.example.com/v1","authorization_servers":' \
                 '["https://issuer.example.com/realms/portal-labs"],"bearer_methods_supported":["header"],' \
                 '"scopes_supported":["orders:read"]}', metadata.document
    assert_equal %(Bearer resource_metadata="#{metadata.url}"), metadata.challenge
    assert_equal %(Bearer error="invalid_token", resource_metadata="#{metadata.url}"), metadata.challenge("invalid_token")
    assert_raises(ArgumentError) { metadata.challenge('x", evil="1') }
    assert metadata.protects?("/v1")
    assert metadata.protects?("/v1/orders")
    refute metadata.protects?("/v10")
    refute metadata.protects?("/health")
  end

  def test_protects_every_path_for_a_resource_at_the_root
    ["https://api.example.com", "https://api.example.com/"].each do |resource|
      metadata = Keelie::ProtectedResourceMetadata.new(resource, ISSUER)
      assert_equal "/.well-known/oauth-protected-resource", metadata.path
      assert metadata.protects?("/anything")
    end
  end

  def test_takes_only_a_plain_lowercase_https_url
    ["http://api.example.com", "https://API.example.com", "HTTPS://api.example.com", "Https://api.example.com",
     "https://api.example.com/v1/", "https://api.example.com/v1?x=1", "https://api.example.com/v1#x",
     "https://user@api.example.com", "https://api.example.com:http", "https://api.example.com:70000",
     "https:///v1", 'https://api.example.com/"', "https://api.example.com/a b", "https://[]/v1", "", nil].each do |bad|
      assert_raises(ArgumentError, bad.inspect) { Keelie::ProtectedResourceMetadata.new(bad, ISSUER) }
    end
    Keelie::ProtectedResourceMetadata.new("https://api.example.com:8443/mcp", ISSUER)
    Keelie::ProtectedResourceMetadata.new("https://[::1]:8443/mcp", ISSUER)
    assert_equal "https://[::1]/.well-known/oauth-protected-resource/x",
                 Keelie::ProtectedResourceMetadata.new("https://[::1]/x", ISSUER).url
    ["https://[::1/x", "https://[::1]x/y", "https://[::1]:x/y", "https://api.example.com:1:2", "https://api.example.com/v1?",
     "https://api.example.com/#"].each do |bad|
      assert_raises(ArgumentError, bad) { Keelie::ProtectedResourceMetadata.new(bad, ISSUER) }
    end
    assert_raises(ArgumentError) { Keelie::ProtectedResourceMetadata.new("https://api.example.com", "http://issuer") }
    assert_raises(ArgumentError) do
      Keelie::ProtectedResourceMetadata.new("https://api.example.com", ISSUER, scopes_supported: "a b")
    end
    assert_raises(ArgumentError) do
      Keelie::ProtectedResourceMetadata.new("https://api.example.com", ISSUER, scopes_supported: ["a b"])
    end
  end

  def test_reads_the_token_of_a_bearer_header_and_nothing_else
    assert_equal "abc", Keelie.bearer_token("Bearer abc")
    assert_equal "abc", Keelie.bearer_token("bearer   abc  ")
    assert_nil Keelie.bearer_token("Basic abc")
    assert_nil Keelie.bearer_token("Bearer")
    assert_nil Keelie.bearer_token("Bearer ")
    assert_nil Keelie.bearer_token(nil)
  end
end
