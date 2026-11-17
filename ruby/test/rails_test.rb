# frozen_string_literal: true

require_relative "support"
require "action_controller"
require "action_dispatch"
require "rack/mock"

module RailsFixtures
  PAIR = Support.key_pair("key-1")
  ISSUER = Support::FakeIssuer.new(PAIR)
  VERIFIER = Keelie::TokenVerifier.new(Support::ISSUER, Support::RESOURCE, Support::ORG_ID,
                                       keys: Keelie::SigningKeys.new(Support::ISSUER, http: ISSUER))
  METADATA = Keelie::ProtectedResourceMetadata.new(Support::RESOURCE, Support::ISSUER)
  SCOPES = Keelie::ScopeMap.new(
    "GET /v1" => "orders:read",
    "GET /v1/orders/:order_id" => "orders:read",
    "POST /v1/orders" => "orders:write",
    "GET /v1/items/:item_id" => "items:read"
  )

  class OrdersController < ActionController::API
    include Keelie::Rails::ScopeCheck
    keelie_scope_check SCOPES, METADATA

    def index = render(json: { route: keelie_route })
    def show = render(json: { order_id: params[:order_id], azp: keelie_claims.azp, route: keelie_route })
    def create = head(:created)
    def unmapped = render(json: {})
  end

  class ItemsController < ActionController::API
    include Keelie::Rails::ScopeCheck
    keelie_scope_check SCOPES, METADATA, only: :show

    def show = render(json: { item_id: params[:item_id] })
    def open = render(json: { open: true })
  end

  class HealthController < ActionController::API
    def show = render(json: { ok: true })
  end

  ROUTES = ActionDispatch::Routing::RouteSet.new.tap do |routes|
    routes.draw do
      get "/health", to: "rails_fixtures/health#show"
      get "/v1", to: "rails_fixtures/orders#index"
      get "/v1/orders/:order_id", to: "rails_fixtures/orders#show"
      post "/v1/orders", to: "rails_fixtures/orders#create"
      get "/v1/unmapped", to: "rails_fixtures/orders#unmapped"
      scope "/v1" do
        get "/items/:item_id", to: "rails_fixtures/items#show"
        get "/open", to: "rails_fixtures/items#open"
      end
    end
  end

  APP = Keelie::Rack::TokenGuard.new(ROUTES, verifier: VERIFIER, metadata: METADATA)
end

class RailsTest < Minitest::Test
  include Support

  def setup
    @request = Rack::MockRequest.new(RailsFixtures::APP)
    @token = sign(RailsFixtures::PAIR)
  end

  def call(method, path, token = @token)
    @request.request(method, path, token ? { "HTTP_AUTHORIZATION" => "Bearer #{token}" } : {})
  end

  def test_gives_the_claims_to_a_route_whose_scope_the_token_carries
    response = call("GET", "/v1/orders/42")
    assert_equal 200, response.status
    assert_equal({ "order_id" => "42", "azp" => "consumer-client", "route" => "GET /v1/orders/:order_id" },
                 JSON.parse(response.body))
  end

  def test_answers_403_to_a_route_whose_scope_the_token_lacks_or_that_is_not_in_the_map
    [%w[POST /v1/orders], %w[GET /v1/unmapped], %w[HEAD /v1/orders/42]].each do |method, path|
      response = call(method, path)
      assert_equal [403, RailsFixtures::METADATA.challenge("insufficient_scope"), ""],
                   [response.status, response["www-authenticate"], response.body], "#{method} #{path}"
    end
  end

  def test_reads_the_template_of_a_route_in_a_scope
    assert_equal 403, call("GET", "/v1/items/7").status
    assert_equal 200, call("GET", "/v1/items/7", sign(RailsFixtures::PAIR, "scope" => "items:read")).status
  end

  def test_checks_only_the_actions_it_is_given
    assert_equal 200, call("GET", "/v1/open").status
    assert_equal 401, call("GET", "/v1/open", nil).status
  end

  def test_refuses_a_request_with_no_token_before_the_controller_runs
    response = call("GET", "/v1/orders/42", nil)
    assert_equal [401, RailsFixtures::METADATA.challenge], [response.status, response["www-authenticate"]]
    assert_equal 200, call("GET", "/health", nil).status
  end

  def test_fails_an_action_whose_scope_check_has_no_token_guard_before_it
    bare = Rack::MockRequest.new(RailsFixtures::ROUTES)
    error = assert_raises(Keelie::Error) { bare.get("/v1/orders/42") }
    assert_match(/TokenGuard/, error.message)
  end

  def test_guards_every_form_of_a_path_that_reaches_rails
    server, url = serve(RailsFixtures::APP)
    {
      "/v1/orders/42" => 200, "//v1/orders/42" => 200, "/v1//orders/42" => 200, "/v1/orders/42/" => 200,
      "/v1/orders/42.json" => 200, "/v1.json" => 200, "/V1/orders/42" => 404, "/%76%31/orders/42" => 404,
      "/v1/../v1/orders/42" => 404, "/x/..%2fv1/orders/42" => 404, "/./v1/orders/42" => 404
    }.each do |target, served|
      status, headers, = raw(url, "GET", target)
      assert_equal [401, RailsFixtures::METADATA.challenge], [status, headers["www-authenticate"]], target
      status, = raw(url, "GET", target, "Authorization" => "Bearer #{@token}")
      assert_equal served, status, "Rails with a token: #{target}"
    end
  ensure
    server&.stop(true)
  end
end
