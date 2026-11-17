# frozen_string_literal: true

require_relative "support"
require "action_controller"
require "action_dispatch"
require "rack/mock"

# The example of docs/ruby.md, "Get started with Rails", run as it is written there: its
# blocks are read from the page, so the example cannot drift from the gem. Rails itself
# is stood in for by what the example touches: the middleware list and the routes.
module DocExample
  Middleware = Struct.new(:stack) do
    def use(klass, *args, **options) = stack << [klass, args, options]
  end

  # Routes drawn in this module, so that "orders#show" finds DocExample::OrdersController.
  Routes = Struct.new(:set) do
    def draw(&block) = set.draw { scope(module: "doc_example") { instance_exec(&block) } }
  end

  Application = Struct.new(:config, :routes)
  Config = Struct.new(:middleware)

  module Rails
    def self.application
      @application ||= Application.new(Config.new(Middleware.new([])),
                                       Routes.new(ActionDispatch::Routing::RouteSet.new))
    end
  end

  def self.blocks
    page = File.read(File.expand_path("../../docs/ruby.md", __dir__), encoding: Encoding::UTF_8)
    section = page[/^## Get started with Rails\n(.*?)^## /m, 1] or raise "no Get started section"
    section.scan(/^```ruby\n(.*?)^```/m).map(&:first).reject { _1.include?("before_worker_shutdown") }
  end

  def self.app
    stack = Rails.application.config.middleware.stack
    stack.reverse.reduce(Rails.application.routes.set) { |app, (klass, args, options)| klass.new(app, *args, **options) }
  end
end

class DocExampleTest < Minitest::Test
  include Support

  KEELIE_URL = "https://keelie.example.test"
  TOKEN_URL = "https://issuer.example.com/token"

  # The issuer, its token endpoint and keelie, behind one HTTP client.
  class World
    attr_reader :events, :mints

    def initialize(pair)
      @issuer = Support::FakeIssuer.new(pair)
      @events = []
      @mints = []
    end

    def call(method, url, body: nil, headers: {})
      case url
      when TOKEN_URL
        @mints << body
        Keelie::Response.new(200, {}, JSON.generate("access_token" => "sdk-token", "expires_in" => 300))
      when "#{KEELIE_URL}/usage-events:report"
        raise "no SDK token" unless headers["Authorization"] == "Bearer sdk-token"

        @events.concat(JSON.parse(body)["events"])
        Keelie::Response.new(202, {}, "{}")
      else @issuer.call(method, url)
      end
    end
  end

  def test_the_rails_example_of_the_docs_runs
    pair = key_pair("key-1")
    world = World.new(pair)
    env = { "KEELIE_URL" => KEELIE_URL, "KEELIE_TOKEN_URL" => TOKEN_URL, "KEELIE_ISSUER" => ISSUER,
            "KEELIE_ORG_ID" => ORG_ID, "KEELIE_RESOURCE" => RESOURCE, "KEELIE_SDK_CLIENT_ID" => "sdk",
            "KEELIE_SDK_CLIENT_SECRET" => "s3cret" }
    saved = env.keys.to_h { [_1, ENV.fetch(_1, nil)] }
    ENV.update(env)
    Keelie::HTTP.default = ->(_timeout) { world }
    blocks = DocExample.blocks
    assert_equal 3, blocks.size
    blocks.each { |code| DocExample.module_eval(code, "docs/ruby.md") }

    request = Rack::MockRequest.new(DocExample.app)
    assert_equal 401, request.get("/v1/orders/42").status
    assert_equal 200, request.get("/.well-known/oauth-protected-resource/v1").status
    lacking = request.get("/v1/orders/42", "HTTP_AUTHORIZATION" => "Bearer #{sign(pair, "scope" => "profile")}")
    assert_equal 403, lacking.status
    token = sign(pair, "consumer_id" => CONSUMER)
    response = request.get("/v1/orders/42", "HTTP_AUTHORIZATION" => "Bearer #{token}")
    assert_equal [200, { "order_id" => "42" }], [response.status, JSON.parse(response.body)]

    DocExample::KEELIE_REPORTER.close
    assert_equal ["grant_type=client_credentials&client_id=sdk&client_secret=s3cret"], world.mints
    assert_equal [["consumer-client", "GET /v1/orders/:order_id", "1", CONSUMER]],
                 world.events.map { _1.values_at("client_id", "capability_key", "credits", "consumer_id") }
  ensure
    Keelie::HTTP.default = nil
    saved&.each { |name, value| value.nil? ? ENV.delete(name) : ENV.store(name, value) }
  end
end
