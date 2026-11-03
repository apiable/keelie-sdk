# frozen_string_literal: true

require_relative "support"
require "rack"
require "mcp"
require "timeout"

class McpTest < Minitest::Test
  include Support

  MCP_RESOURCE = "https://api.example.com/mcp"

  # The body each request carried when it reached the MCP server.
  class Seen
    attr_reader :bodies

    def initialize(app)
      @app = app
      @bodies = []
    end

    def call(env)
      if env["REQUEST_METHOD"] == "POST"
        @bodies << env["rack.input"].read
        env["rack.input"].rewind
      end
      @app.call(env)
    end
  end

  def setup
    @pair = key_pair("key-1")
    verifier = Keelie::TokenVerifier.new(ISSUER, MCP_RESOURCE, ORG_ID,
                                         keys: Keelie::SigningKeys.new(ISSUER, http: FakeIssuer.new(@pair)))
    @metadata = Keelie::ProtectedResourceMetadata.new(MCP_RESOURCE, ISSUER)
    @keelie = FakeKeelie.new
    @reporter = Keelie::UsageReporter.new(@keelie, batch_size: 1, flush_interval_seconds: 0.02)

    classify = MCP::Tool.define(name: "classify", description: "Classify a product") do |**|
      MCP::Tool::Response.new([{ type: "text", text: "Apparel > Shoes" }])
    end
    delete_all = MCP::Tool.define(name: "delete_all", description: "Delete everything") do |**|
      MCP::Tool::Response.new([{ type: "text", text: "gone" }])
    end
    server = MCP::Server.new(name: "product-classifier", version: "1.0.0", tools: [classify, delete_all])
    transport = MCP::Server::Transports::StreamableHTTPTransport.new(server, stateless: true)
    @seen = Seen.new(transport)
    seen = @seen
    metadata = @metadata
    reporter = @reporter
    app = Rack::Builder.app do
      use Keelie::Rack::McpGuard, verifier: verifier, metadata: metadata, reporter: reporter,
                                  tools: { "classify" => "classify:run", delete_all: "admin" }, max_body_bytes: 4096
      map("/mcp") { run seen }
    end
    @server, @url = serve(app)
    @token = sign(@pair, "aud" => MCP_RESOURCE, "scope" => "classify:run", "consumer_id" => CONSUMER,
                         "azp" => "claude")
  end

  def teardown
    capture_log { @reporter.close(1) }
    @server.stop(true)
  end

  def post(body, auth: "Bearer #{@token}", method: "POST")
    headers = { "Content-Type" => "application/json", "Accept" => "application/json, text/event-stream" }
    headers["Authorization"] = auth if auth
    raw(@url, method, "/mcp", headers, %w[GET HEAD DELETE].include?(method) ? nil : body)
  end

  def assert_rpc_error(response, status, code, id = nil)
    assert_equal status, response[0]
    assert_equal "application/json", response[1]["content-type"]
    body = JSON.parse(response[2])
    assert_equal [code, id], [body["error"]["code"], body["id"]]
  end

  def test_lets_a_real_mcp_client_list_and_call_a_tool_its_token_allows_and_counts_the_call
    http = MCP::Client::HTTP.new(url: "#{@url}/mcp", headers: { "Authorization" => "Bearer #{@token}" })
    client = MCP::Client.new(transport: http)
    client.connect
    assert_equal %w[classify delete_all], client.tools.map(&:name).sort
    result = client.call_tool(name: "classify", arguments: {})
    assert_equal [{ "type" => "text", "text" => "Apparel > Shoes" }], result.dig("result", "content")
    assert_raises(StandardError) { client.call_tool(name: "delete_all", arguments: {}) }
    http.close if http.respond_to?(:close)

    wait_until { @keelie.sent.any? }
    sleep 0.1
    calls = @keelie.sent.flat_map(&:events).select { _1["unit"] == "tool_call" }
    assert_equal 1, calls.size
    assert_equal %w[classify claude], calls[0].values_at("capability_key", "client_id")
    assert_equal CONSUMER, calls[0]["consumer_id"]
    refute calls[0].key?("credits")
  end

  def test_answers_a_tool_its_token_lacks_or_that_is_not_mapped_with_403_and_no_scope_named
    %w[delete_all not_a_tool].each do |name|
      response = post(JSON.generate("jsonrpc" => "2.0", "id" => 7, "method" => "tools/call", "params" => { "name" => name }))
      assert_equal @metadata.challenge("insufficient_scope"), response[1]["www-authenticate"]
      assert_rpc_error response, 403, -31_001, 7
      refute_includes response[2], "admin"
    end
  end

  def test_refuses_what_two_parsers_could_read_in_two_ways
    assert_rpc_error post('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify","name":"delete_all"}}'),
                     400, -32_600
    assert_rpc_error post('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify","na\u006de":"delete_all"}}'),
                     400, -32_600
    assert_rpc_error post('[{"jsonrpc":"2.0","id":1,"method":"ping"}]'), 400, -32_600
    assert_rpc_error post('"just a string"'), 400, -32_600
    assert_rpc_error post("{not json"), 400, -32_700
    assert_rpc_error post(("[" * 1001) + ("]" * 1001)), 400, -32_700
    assert_rpc_error post("\uFEFF{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"), 400, -32_700
    assert_rpc_error post("{\"a\":\"\xff\"}".b), 400, -32_700
  end

  # A comment holding one quote once sent the guard's scan into an endless loop. Older
  # json gems read comments; the guard refuses them, as Python's parser does.
  def test_refuses_a_comment_at_once
    ['{"jsonrpc":"2.0","id":1,"method":"ping" /* " */}',
     %({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify"} // "\n}),
     '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify" /* { */,"name":"delete_all"}}'].each do |body|
      Timeout.timeout(2) { assert_rpc_error post(body), 400, -32_700 }
    end
    assert_empty @seen.bodies
  end

  def test_refuses_a_tool_call_with_no_id_or_a_name_that_is_not_a_string
    assert_rpc_error post('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"classify"}}'), 400, -32_600
    assert_rpc_error post('{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"classify"}}'), 400, -32_600
    assert_rpc_error post('{"jsonrpc":"2.0","id":1.5,"method":"tools/call","params":{"name":"classify"}}'), 400, -32_600
    assert_rpc_error post('{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":3}}'), 400, -32_602, "a"
    assert_rpc_error post('{"jsonrpc":"2.0","id":"a","method":"tools/call"}'), 400, -32_602, "a"
  end

  def test_refuses_a_body_over_the_limit_with_413
    body = JSON.generate("jsonrpc" => "2.0", "id" => 1, "method" => "ping", "pad" => "x" * 5000)
    assert_rpc_error post(body), 413, -32_600
  end

  def test_lets_get_and_delete_pass_and_refuses_any_other_method_with_405
    refute_equal 401, post(nil, method: "GET")[0] # the server's own answer
    put = post("{}", method: "PUT")
    assert_equal [405, "GET, POST, DELETE"], [put[0], put[1]["allow"]]
  end

  def test_checks_the_token_first
    none = post("{}", auth: nil)
    assert_equal [401, @metadata.challenge], [none[0], none[1]["www-authenticate"]]
    bad = post("{}", auth: "Bearer nope")
    assert_equal [401, @metadata.challenge("invalid_token")], [bad[0], bad[1]["www-authenticate"]]
  end

  def test_hands_the_body_it_checked_to_the_server
    body = '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"classify","arguments":{}}}'
    status, = post(body)
    assert_equal 200, status
    assert_equal [body], @seen.bodies
    wait_until { @keelie.sent.any? }
  end

  def test_records_a_tool_call_only_when_the_server_answers_2xx
    call = '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"classify","arguments":{}}}'
    refused = raw(@url, "POST", "/mcp", { "Authorization" => "Bearer #{@token}", "Content-Type" => "application/json",
                                          "Accept" => "text/html" }, call)
    assert_equal 406, refused[0] # the server's own refusal: it wants an Accept it can answer
    assert_equal 200, post('{"jsonrpc":"2.0","id":10,"method":"ping"}')[0]
    sleep 0.1
    assert_empty @keelie.sent
    assert_equal 200, post(call)[0]
    wait_until { @keelie.sent.any? }
    assert_equal ["tool_call"], @keelie.sent.flat_map(&:events).map { _1["unit"] }
  end
end

# The scan behind the MCP guard, on texts the installed json gem may not let it see.
class StrictJSONScanTest < Minitest::Test
  def scan(text)
    Timeout.timeout(2) { Keelie::StrictJSON.scan(text) }
  end

  def test_refuses_a_comment_whatever_it_holds
    # The text reported: a comment holding one quote.
    ['{"a":1 /* " */}', %({"a":1 // "\n}), '{"a":1 /* { */}', '{"a":1 /* } */}', '{"a":1 /**/}',
     '/* */ {"a":1}', '{"a":1} /'].each do |text|
      assert_raises(JSON::ParserError, text) { scan(text) }
    end
  end

  def test_ends_on_a_text_cut_short_or_with_a_stray_byte
    ['"', '"ab', '"ab\\', '"\\', '{"a":"b', '{"a":"b\\"}', "*", "{\"a\":1}*", "{\"a\":1}\\", "'a'", "{\"a\":1}\v",
     "{\"a\":1}\f", "{\"a\":\"x\"}\u00a0".b].each do |text|
      assert_raises(JSON::ParserError, text) { scan(text) }
    end
  end

  def test_reads_json_as_before
    ['{"a":"/* \\" */","b":[1,-2.5e+3,true,false,null,NaN,-Infinity]}', " \t\r\n{}", '["\\\\"]',
     '{"a":{"a":1},"b":{"a":2}}'].each do |text|
      assert_nil scan(text)
    end
    assert_raises(Keelie::StrictJSON::DuplicateKey) { scan('{"x":1, "y":{}, "x":2}') }
    assert_raises(Keelie::StrictJSON::DuplicateKey) { scan('{"a":1,"\\u0061":2}') }
  end
end
