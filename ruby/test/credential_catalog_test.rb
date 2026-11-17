# frozen_string_literal: true

require_relative "support"

class CredentialTest < Minitest::Test
  include Support

  TOKEN_URL = "https://issuer.example.com/token"

  # A token endpoint and a keelie, in one HTTP client.
  class Endpoints
    attr_reader :calls, :minted
    attr_accessor :refuse, :token_status, :lifetime

    def initialize
      @calls = []
      @minted = 0
      @refuse = false
      @token_status = 200
      @lifetime = 300
      @lock = Mutex.new
    end

    def call(method, url, body: nil, headers: {})
      @lock.synchronize { @calls << [method, url, headers["Authorization"], body, headers] }
      if url == TOKEN_URL
        sleep 0.05 # so that threads overlap on the mint
        @lock.synchronize { @minted += 1 }
        token = { "access_token" => "token-#{@minted}", "expires_in" => @lifetime }
        return Keelie::Response.new(@token_status, {}, JSON.generate(token))
      end
      if @refuse
        @refuse = false
        return Keelie::Response.new(401, {}, "")
      end
      Keelie::Response.new(200, {}, '{"ok":true}')
    end
  end

  def credential(endpoints, clock: nil)
    Keelie::SdkCredential.new(keelie_url: "https://keelie.example/", token_url: TOKEN_URL, client_id: "sdk",
                              client_secret: "s3cret", http: endpoints, clock: clock)
  end

  def test_mints_a_token_once_sends_it_and_mints_again_on_a_401
    endpoints = Endpoints.new
    keelie = credential(endpoints)
    Array.new(4) { Thread.new { keelie.call("GET", "/ai-catalog") } }.each(&:join)
    assert_equal 1, endpoints.minted
    mint = endpoints.calls.first
    assert_equal ["POST", TOKEN_URL, nil, "grant_type=client_credentials&client_id=sdk&client_secret=s3cret"], mint[0, 4]
    assert_equal "application/x-www-form-urlencoded", mint[4]["Content-Type"]
    assert_equal [["GET", "https://keelie.example/ai-catalog", "Bearer token-1"]] * 4,
                 endpoints.calls.drop(1).map { _1[0, 3] }
    endpoints.refuse = true
    response = keelie.call("POST", "/usage-events:report", body: "{}", headers: { "Idempotency-Key" => "k" })
    assert_equal 200, response.status
    assert_equal 2, endpoints.minted
    assert_equal ["POST", "https://keelie.example/usage-events:report", "Bearer token-2", "{}"], endpoints.calls.last[0, 4]
    assert_equal "k", endpoints.calls.last[4]["Idempotency-Key"]
  end

  def test_mints_again_before_the_token_expires
    endpoints = Endpoints.new
    clock = Clock.new
    keelie = credential(endpoints, clock: clock)
    keelie.call("GET", "/ai-catalog")
    clock.now += 269
    keelie.call("GET", "/ai-catalog")
    assert_equal 1, endpoints.minted
    clock.now += 1 # 300 - 30 seconds
    keelie.call("GET", "/ai-catalog")
    assert_equal 2, endpoints.minted
    endpoints.lifetime = 40 # max(40 - 30, 40 / 2) = 20 seconds
    clock.now += 300
    keelie.call("GET", "/ai-catalog")
    clock.now += 19
    keelie.call("GET", "/ai-catalog")
    assert_equal 3, endpoints.minted
    clock.now += 1
    keelie.call("GET", "/ai-catalog")
    assert_equal 4, endpoints.minted
  end

  def test_raises_when_the_token_endpoint_refuses_and_never_shows_the_secret
    endpoints = Endpoints.new
    endpoints.token_status = 401
    keelie = credential(endpoints)
    error = assert_raises(Keelie::Error) { keelie.call("GET", "/ai-catalog") }
    assert_equal "the token endpoint answered 401", error.message
    refute_includes keelie.inspect, "s3cret"
  end
end

class CatalogTest < Minitest::Test
  include Support

  DOCUMENT = '{"specVersion":"0.91","entries":[]}'

  def setup
    @clock = Clock.new
    @answers = []
    @fetched = 0
    @lock = Mutex.new
    test = self
    keelie = Object.new
    keelie.define_singleton_method(:call) { |method, path, **| test.fetch(method, path) }
    @metadata = Keelie::ProtectedResourceMetadata.new(RESOURCE, ISSUER)
    @catalog = Keelie::AiCatalog.new(keelie, @metadata, clock: @clock)
  end

  def fetch(method, path)
    assert_equal ["GET", "/ai-catalog"], [method, path]
    answer = @lock.synchronize do
      @fetched += 1
      @answers.shift || 200
    end
    sleep 0.05
    raise Errno::ECONNREFUSED, "keelie down" if answer == :network

    Keelie::Response.new(answer, {}, answer == 200 ? DOCUMENT : "")
  end

  def test_tells_the_guards_that_its_paths_need_no_token
    assert @metadata.ai_catalog
  end

  def test_serves_one_body_at_both_paths_with_their_media_types_and_keeps_it_60_seconds
    status, headers, body = @catalog.answer("/.well-known/ard.json")
    assert_equal [200, "application/json", "max-age=60", [DOCUMENT]],
                 [status, headers["content-type"], headers["cache-control"], body]
    _, headers, = @catalog.answer("/.well-known/ai-catalog.json")
    assert_equal "application/ai-catalog+json", headers["content-type"]
    assert_equal 1, @fetched
    @clock.now += 59
    @catalog.answer("/.well-known/ard.json")
    assert_equal 1, @fetched
    @clock.now += 1
    @catalog.answer("/.well-known/ard.json")
    assert_equal 2, @fetched
    assert_nil @catalog.answer("/other")
  end

  def test_answers_503_when_keelie_fails_never_an_old_copy_and_asks_again_after_10_seconds
    capture_log do |lines|
      @catalog.answer("/.well-known/ard.json")
      @clock.now += 60
      @answers << 500
      status, headers, body = @catalog.answer("/.well-known/ard.json")
      assert_equal [503, "10", "no-store", []], [status, headers["retry-after"], headers["cache-control"], body]
      assert_includes lines, "apiable.catalog_fetch_failed status=500"
      @clock.now += 9
      assert_equal 503, @catalog.answer("/.well-known/ard.json")[0]
      assert_equal 2, @fetched
      @clock.now += 1
      @answers << :network
      assert_equal 503, @catalog.answer("/.well-known/ard.json")[0]
      assert_includes lines, "apiable.catalog_fetch_failed error=Errno::ECONNREFUSED"
      @clock.now += 10
      assert_equal 200, @catalog.answer("/.well-known/ard.json")[0]
      assert_equal 4, @fetched
    end
  end

  def test_makes_one_fetch_for_many_requests_at_once
    statuses = Array.new(10) { Thread.new { @catalog.answer("/.well-known/ard.json")[0] } }.map(&:value)
    assert_equal [200] * 10, statuses
    assert_equal 1, @fetched
  end
end
