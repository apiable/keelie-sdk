# frozen_string_literal: true

require_relative "support"
require "rack"
require "rack/mock"

class RackTest < Minitest::Test
  include Support

  # Serves any path, and says what it saw: the path and the claims' azp.
  ECHO = lambda do |env|
    claims = env[Keelie::Rack::CLAIMS_KEY]
    [200, { "content-type" => "application/json" },
     [JSON.generate("path" => env["PATH_INFO"], "azp" => claims&.azp)]]
  end

  def setup
    @pair = key_pair("key-1")
    @issuer = FakeIssuer.new(@pair)
    @verifier = Keelie::TokenVerifier.new(ISSUER, RESOURCE, ORG_ID,
                                          keys: Keelie::SigningKeys.new(ISSUER, http: @issuer))
    @metadata = Keelie::ProtectedResourceMetadata.new(RESOURCE, ISSUER)
    keelie = ->(_method, _path, **) { Keelie::Response.new(200, {}, '{"entries":[]}') }
    catalog = Keelie::AiCatalog.new(keelie, @metadata)
    verifier = @verifier
    metadata = @metadata
    @app = Rack::Lint.new(Rack::Builder.app do
      use Rack::Lint
      use Keelie::Rack::AiCatalog, catalog: catalog
      use Rack::Lint
      use Keelie::Rack::TokenGuard, verifier: verifier, metadata: metadata
      use Rack::Lint
      run ECHO
    end)
    @request = Rack::MockRequest.new(@app)
  end

  def get(path, token = nil, method: "GET")
    env = { method: method }
    env["HTTP_AUTHORIZATION"] = token if token
    @request.request(method, path, env)
  end

  def test_serves_the_metadata_with_no_token
    response = get("/.well-known/oauth-protected-resource/v1")
    assert_equal [200, "application/json", @metadata.document], [response.status, response.content_type, response.body]
    head = get("/.well-known/oauth-protected-resource/v1", method: "HEAD")
    assert_equal [200, @metadata.document.bytesize.to_s, ""], [head.status, head["content-length"], head.body]
  end

  def test_refuses_a_request_with_no_token_and_names_the_metadata
    response = get("/v1/orders/42")
    assert_equal [401, @metadata.challenge, ""], [response.status, response["www-authenticate"], response.body]
    assert_equal 401, get("/v1/orders/42", "Basic abc").status
  end

  def test_refuses_a_bad_token_the_same_way_for_every_reason
    ["Bearer nope", "Bearer #{sign(@pair, "org_id" => OTHER_ORG)}", "Bearer #{sign(@pair, "exp" => 1)}"].each do |bad|
      response = get("/v1/orders/42", bad)
      assert_equal [401, @metadata.challenge("invalid_token"), ""],
                   [response.status, response["www-authenticate"], response.body]
    end
  end

  def test_gives_the_claims_to_the_app
    response = get("/v1/orders/42", "Bearer #{sign(@pair)}")
    assert_equal 200, response.status
    assert_equal({ "path" => "/v1/orders/42", "azp" => "consumer-client" }, JSON.parse(response.body))
  end

  def test_lets_paths_outside_resource_and_a_preflight_pass_untouched
    assert_equal 200, get("/health").status
    assert_equal 200, get("/v10/orders").status
    assert_equal 200, get("/v1/orders/42", method: "OPTIONS").status
  end

  def test_serves_the_ai_catalog_with_no_token_and_guards_any_other_method_on_it
    response = get("/.well-known/ai-catalog.json")
    assert_equal [200, "application/ai-catalog+json", '{"entries":[]}'],
                 [response.status, response.content_type, response.body]
    assert_equal "", get("/.well-known/ard.json", method: "HEAD").body
    root = Keelie::ProtectedResourceMetadata.new("https://api.example.com", ISSUER)
    guard = Keelie::Rack::TokenGuard.new(ECHO, verifier: Keelie::TokenVerifier.new(ISSUER, root.resource, ORG_ID),
                                               metadata: root)
    assert_equal 401, Rack::MockRequest.new(guard).get("/.well-known/ai-catalog.json").status
    Keelie::AiCatalog.new(->(*, **) {}, root)
    assert_equal 200, Rack::MockRequest.new(guard).get("/.well-known/ai-catalog.json").status
    assert_equal 401, Rack::MockRequest.new(guard).post("/.well-known/ai-catalog.json").status
    assert_equal 200, Rack::MockRequest.new(guard).get("/.well-known/oauth-protected-resource").status
    assert_equal 401, Rack::MockRequest.new(guard).post("/.well-known/oauth-protected-resource").status
  end

  def test_reads_the_path_the_client_sent_under_a_mounted_app
    mounted = Rack::Builder.app do
      map("/v1") { run Keelie::Rack::TokenGuard.new(ECHO, verifier: Keelie::TokenVerifier.new(ISSUER, RESOURCE, ORG_ID),
                                                          metadata: Keelie::ProtectedResourceMetadata.new(RESOURCE, ISSUER)) }
    end
    assert_equal 401, Rack::MockRequest.new(mounted).get("/v1/orders/42").status
  end

  def test_does_not_start_when_the_verifiers_audience_is_not_the_resource
    verifier = Keelie::TokenVerifier.new(ISSUER, "https://api.example.com/v2", ORG_ID)
    assert_raises(ArgumentError) { Keelie::Rack::TokenGuard.new(ECHO, verifier: verifier, metadata: @metadata) }
  end

  def test_compares_every_form_of_a_path_a_router_could_route_by
    {
      "/v1/orders/42" => "/v1/orders/42",
      "/V1/orders/42" => "/V1/orders/42",
      "/%76%31/orders/42" => "/v1/orders/42",
      "//v1/orders/42" => "/v1/orders/42",
      "/x/..%2fv1/orders" => "/v1/orders",
      "/x/%2e%2e/v1" => "/v1",
      "/x\\..\\v1" => "/v1",
      "/%2576%2531/a" => "/v1/a",
      "/v1.json" => "/v1"
    }.each do |path, form|
      assert_includes Keelie::Rack.forms(path), form.b, path
    end
    assert_equal ["/health"], Keelie::Rack.forms("/health").uniq
  end

  # A router that serves a path by its most normalized form, without case and without a
  # format extension: Sinatra behind rack-protection resolves "..", "%2e" and "%2f"
  # before the route is matched, Rails drops ".json", Express ignores case.
  NORMALIZING_ROUTER = lambda do |env|
    path = Keelie::Rack.normalized(env["PATH_INFO"]).last.downcase
    return [404, {}, []] unless path.start_with?("/v1/orders/")

    [200, {}, ["order #{path.split("/").last} for #{env[Keelie::Rack::CLAIMS_KEY]&.azp.inspect}"]]
  end

  def test_guards_every_form_of_a_path_that_reaches_the_server
    guard = Keelie::Rack::TokenGuard.new(NORMALIZING_ROUTER, verifier: @verifier, metadata: @metadata)
    server, url = serve(guard)
    ["/v1/orders/42", "/V1/orders/42", "/v1/../v1/orders/42", "/%76%31/orders/42", "//v1/orders/42",
     "/x/..%2fv1/orders/42", "/x/%2e%2e/v1/orders/42", "/x/..%5cv1/orders/42", "/%2576%2531/orders/42",
     "/./v1/orders/42", "/v1/orders/42.json", "http://127.0.0.1/v1/orders/42"].each do |target|
      status, headers, = raw(url, "GET", target)
      assert_equal 401, status, target
      assert_equal @metadata.challenge, headers["www-authenticate"], target
      status, _, body = raw(url, "GET", target, "Authorization" => "Bearer #{sign(@pair)}")
      assert_equal [200, 'order 42 for "consumer-client"'], [status, body], target
    end
  ensure
    server&.stop(true)
  end
end
