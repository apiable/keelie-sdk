# frozen_string_literal: true

require_relative "support"
require "rack"
require "rack/mock"

# One core serves both adapters: the same token check, through both. And keelie being
# unreachable changes nothing on the request path.
class AdaptersTest < Minitest::Test
  include Support

  PROVIDER = ->(_env) { [200, { "content-type" => "application/json" }, ["{}"]] }
  TOOLS_LIST = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

  def setup
    @pair = key_pair("key-1")
    @issuer = FakeIssuer.new(@pair)
    @clock = Clock.new
    @verifier = Keelie::TokenVerifier.new(ISSUER, RESOURCE, ORG_ID,
                                          keys: Keelie::SigningKeys.new(ISSUER, http: @issuer, clock: @clock))
    @metadata = Keelie::ProtectedResourceMetadata.new(RESOURCE, ISSUER)
  end

  def adapters(verifier = @verifier)
    {
      rest: Keelie::Rack::TokenGuard.new(PROVIDER, verifier: verifier, metadata: @metadata),
      mcp: Keelie::Rack::McpGuard.new(PROVIDER, verifier: verifier, metadata: @metadata,
                                                tools: {}, reporter: Keelie::UsageReporter.new(FakeKeelie.new))
    }
  end

  def post(app, authorization, path = "/v1", headers: {})
    env = { "CONTENT_TYPE" => "application/json", input: TOOLS_LIST }.merge(headers)
    env["HTTP_AUTHORIZATION"] = authorization if authorization
    Rack::MockRequest.new(app).post(path, env)
  end

  def test_both_adapters_answer_each_token_the_same
    refusal = @metadata.challenge("invalid_token")
    [
      [sign(@pair), 200, nil],
      [nil, 401, @metadata.challenge],
      [sign(@pair, "exp" => Time.now.to_i - 31), 401, refusal],
      [sign(@pair, "org_id" => OTHER_ORG), 401, refusal],
      [sign(@pair, "aud" => "another-api"), 401, refusal],
      [sign(key_pair("key-1", index: 1)), 401, refusal],
      ["not-a-token", 401, refusal]
    ].each do |token, status, challenge|
      adapters.each do |name, app|
        response = post(app, token && "Bearer #{token}")
        assert_equal [status, challenge], [response.status, response["www-authenticate"]], "#{name} #{token.inspect}"
        assert_equal "", response.body if status == 401
      end
    end
  end

  def test_neither_adapter_starts_for_an_audience_that_is_not_the_resource
    elsewhere = Keelie::TokenVerifier.new(ISSUER, "https://api.example.com/other", ORG_ID)
    error = assert_raises(ArgumentError) { adapters(elsewhere) }
    assert_match(/is not the resource/, error.message)
    assert_raises(ArgumentError) do
      Keelie::Rack::McpGuard.new(PROVIDER, verifier: elsewhere, metadata: @metadata, tools: {}, reporter: nil)
    end
  end

  def test_a_path_outside_the_resource_passes_both_adapters_untouched
    adapters.each_value { |app| assert_equal 200, post(app, nil, "/health").status }
  end

  def test_a_forged_host_does_not_move_the_challenge
    adapters.each_value do |app|
      response = post(app, nil, headers: { "HTTP_HOST" => "evil.example", "HTTP_X_FORWARDED_HOST" => "evil.example" })
      assert_equal @metadata.challenge, response["www-authenticate"]
    end
  end

  def test_no_file_outside_the_core_holds_its_own_token_check
    lib = File.expand_path("../lib/keelie", __dir__)
    Dir["#{lib}/**/*.rb"].each do |path|
      source = File.read(path, encoding: Encoding::UTF_8)
      next if %w[tokens.rb keys.rb].include?(File.basename(path))

      calls = source.scan(/\.verify\(/).size
      expected = File.basename(path) == "rack.rb" ? 1 : 0 # Guard#call, and nothing else
      assert_equal expected, calls, "#{path} calls .verify itself"
      refute_match(/OpenSSL|SigningKeys\.new|\.key\(/, source, "#{path} reads keys itself")
    end
  end

  # keelie is unreachable for 20 minutes, and Consumers call the Provider's API. The token
  # carries the decision: the SDK serves every call while a token lives, and refuses when
  # it expires. It asks keelie for nothing on the way.
  def test_consumers_during_a_20_minute_outage
    {
      "large balance" => [3600, 200],
      "balance reaches zero, token alive" => [120, 200],
      "balance reaches zero, token expired" => [-31, 401],
      "delinquent" => [-600, 401],
      "never seen" => [nil, 401]
    }.each do |consumer, (expires_in, status)|
      setup
      guard = adapters[:rest]
      assert_equal 200, post(guard, "Bearer #{sign(@pair)}").status # before the outage, one call loads the keys
      @issuer.down = true
      @clock.now += 20 * 60
      token = expires_in && sign(@pair, "exp" => Time.now.to_i + expires_in)
      assert_equal status, post(guard, token && "Bearer #{token}").status, consumer
      # The SDK asked the issuer nothing during the outage, so the status does not show it.
      assert_equal 1, @issuer.jwks_fetches
      assert_equal :connected, @verifier.status
    end
  end
end
