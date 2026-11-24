# frozen_string_literal: true

require_relative "support"

class HTTPTest < Minitest::Test
  include Support

  # A server on 127.0.0.1 that answers each request with +answer+, a byte every
  # +pause+ seconds. It then holds the connection open for +hold+ seconds.
  def drip(answer, pause, hold: 0)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        Thread.new(server.accept) do |socket|
          socket.readpartial(65_536)
          answer.each_char do |char|
            socket.write(char)
            sleep pause
          end
          sleep hold
        rescue IOError, SystemCallError
          nil
        ensure
          socket.close
        end
      end
    rescue IOError
      nil
    end
    yield "http://127.0.0.1:#{server.addr[1]}"
  ensure
    server&.close
    thread&.kill
  end

  def timed
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  def test_reads_an_answer
    drip("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: b\r\n\r\nok", 0) do |url|
      response = Keelie::HTTP.new(1).call("GET", "#{url}/x")
      assert_equal [200, "b", "ok"], [response.status, response.headers["x-a"], response.body]
    end
  end

  # Net::HTTP's read timeout bounds each wait, not the answer. The SDK bounds the answer.
  def test_cuts_off_a_server_that_sends_one_byte_at_a_time
    ["HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n#{"x" * 100}",
     "HTTP/1.1 200 OK\r\nX-Padding: #{"y" * 100}\r\n\r\n"].each do |answer|
      drip(answer, 0.05) do |url|
        elapsed = timed { assert_raises(Net::ReadTimeout) { Keelie::HTTP.new(0.5).call("GET", "#{url}/x") } }
        assert_operator elapsed, :<, 1.0
      end
    end
  end

  # A proxy from the environment answers CONNECT before the SDK wraps the socket. The
  # deadline bounds that exchange too.
  def with_proxy(answer, pause, hold: 0)
    drip(answer, pause, hold: hold) do |proxy|
      saved = %w[http_proxy HTTP_PROXY no_proxy NO_PROXY].to_h { [_1, ENV.fetch(_1, nil)] }
      saved.each_key { ENV.delete(_1) }
      ENV["http_proxy"] = proxy
      yield
    ensure
      saved&.each { |name, value| value.nil? ? ENV.delete(name) : ENV[name] = value }
    end
  end

  def test_bounds_the_connect_exchange_with_a_silent_proxy_by_the_deadline
    with_proxy("", 0, hold: 3) do
      elapsed = timed do
        assert_raises(Net::ReadTimeout) { Keelie::HTTP.new(0.5).call("GET", "https://issuer.example.com/x") }
      end
      assert_operator elapsed, :<, 1.0
    end
  end

  def test_cuts_off_a_proxy_that_answers_connect_one_byte_at_a_time
    skip "this net-http has no timeouted_connect" unless Net::HTTP.private_method_defined?(:timeouted_connect)

    with_proxy("HTTP/1.1 200 Connection established\r\nX-Padding: #{"y" * 100}\r\n\r\n", 0.1) do
      elapsed = timed do
        assert_raises(Net::ReadTimeout) { Keelie::HTTP.new(0.5).call("GET", "https://issuer.example.com/x") }
      end
      assert_operator elapsed, :<, 1.0
    end
  end

  def test_sends_to_https_or_to_plain_http_on_a_loopback_host_only
    %w[http://issuer.example.com/x http://10.0.0.1/x http://localhost.example.com/x ftp://localhost/x].each do |url|
      assert_raises(ArgumentError, url) { Keelie::HTTP.new(1).call("GET", url) }
    end
    assert Keelie::HTTP.secure_url?("https://issuer.example.com/x")
    assert Keelie::HTTP.secure_url?("HTTPS://issuer.example.com/x")
    %w[http://localhost:8080/x http://LOCALHOST/x http://127.0.0.1/x http://[::1]:8080/x].each do |url|
      assert Keelie::HTTP.secure_url?(url), url
    end
    refute Keelie::HTTP.secure_url?("https:///x")
    refute Keelie::HTTP.secure_url?("https://user@issuer.example.com/x")
    refute Keelie::HTTP.secure_url?("https://user:pass@issuer.example.com/x")
    refute Keelie::HTTP.secure_url?("http://user@localhost/x")
    assert_raises(ArgumentError) { Keelie::HTTP.secure_url!("token_url", "https://user@issuer.example.com/x") }
    refute Keelie::HTTP.secure_url?("not a url")
  end
end
