# frozen_string_literal: true

# A fake issuer, a fake keelie and a running Puma server, for the tests. No network.

require "minitest/autorun"
require "json"
require "openssl"
require "socket"
require "keelie"

module Support
  ISSUER = "https://issuer.example.com/realms/portal-labs"
  JWKS_URI = "#{ISSUER}/protocol/openid-connect/certs".freeze
  RESOURCE = "https://api.example.com/v1"
  ORG_ID = "6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12"
  OTHER_ORG = "0f2e1d3c-5b4a-4968-8776-a5b4c3d2e1f0"
  CONSUMER = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
  # Leave a claim out of a token.
  ABSENT = Object.new.freeze

  KeyPair = Struct.new(:kid, :private_key, :jwk)

  # Keys are slow to make, so the tests share a few.
  KEYS = Hash.new { |cache, bits| cache[bits] = OpenSSL::PKey::RSA.generate(bits) }
  POOL = Array.new(3) { OpenSSL::PKey::RSA.generate(2048) }

  module_function

  def b64(bytes) = [bytes].pack("m0").tr("+/", "-_").delete("=")

  # A key pair. +index+ picks one of the shared keys: give two kids the same index for
  # an impostor with the same key, or another index for another key.
  def key_pair(kid, index: 0, bits: nil)
    key = bits ? KEYS[bits] : POOL.fetch(index)
    jwk = { "kty" => "RSA", "kid" => kid, "use" => "sig", "alg" => "RS256",
            "n" => b64(key.n.to_s(2)), "e" => b64(key.e.to_s(2)) }
    KeyPair.new(kid, key, jwk)
  end

  # The claims of a Consumer's token, by the token rules.
  def claims(extra = {})
    now = Time.now.to_i
    {
      "iss" => ISSUER, "aud" => RESOURCE, "azp" => "consumer-client", "org_id" => ORG_ID,
      "scope" => "orders:read profile", "typ" => "Bearer", "jti" => "token-1",
      "sub" => "service-account-user", "iat" => now, "exp" => now + 300
    }.merge(extra).reject { |_, value| value.equal?(ABSENT) }
  end

  # A token signed with +pair+. A claim given as ABSENT is left out.
  def sign(pair, extra = {}, header = {})
    head = { "alg" => "RS256", "kid" => pair.kid }.merge(header).reject { |_, value| value.equal?(ABSENT) }
    input = "#{b64(JSON.generate(head))}.#{b64(JSON.generate(claims(extra)))}"
    "#{input}.#{b64(pair.private_key.sign(OpenSSL::Digest.new("SHA256"), input))}"
  end

  # An unsigned token with any header, for the checks that run before a key is fetched.
  def unsigned(header, payload = claims)
    "#{b64(JSON.generate(header))}.#{b64(JSON.generate(payload))}.#{b64("sig")}"
  end

  # An issuer that serves its discovery document and key set, and counts the requests.
  # It is an HTTP client for SigningKeys: it answers +call+ with no network.
  class FakeIssuer
    attr_accessor :keys, :down, :discovery_issuer, :delay
    attr_reader :requests

    def initialize(pair, issuer: ISSUER)
      @issuer = issuer
      @jwks_uri = "#{issuer}/protocol/openid-connect/certs"
      @keys = [pair.jwk]
      @down = false
      @discovery_issuer = issuer
      @delay = 0
      @requests = []
      @lock = Mutex.new
    end

    def jwks_fetches = @lock.synchronize { @requests.count(@jwks_uri) }

    def call(method, url, body: nil, headers: {})
      raise ArgumentError, method unless method == "GET" && body.nil? && headers.empty?

      @lock.synchronize { @requests << url }
      # Wait, as a real fetch does, so that concurrent callers overlap.
      sleep(@delay) if @delay.positive?
      raise Errno::ECONNREFUSED, "issuer down" if @down

      case url
      when "#{@issuer}/.well-known/openid-configuration"
        json(200, { "issuer" => @discovery_issuer, "jwks_uri" => @jwks_uri })
      when @jwks_uri then json(200, { "keys" => @keys })
      else Keelie::Response.new(404, {}, "")
      end
    end

    def json(status, value) = Keelie::Response.new(status, { "content-type" => "application/json" }, JSON.generate(value))
  end

  # A keelie whose next answers the test sets: a status, or :network for a network
  # error. It answers 202 when none is set.
  class FakeKeelie
    Sent = Struct.new(:method, :path, :key, :events, :headers)

    attr_reader :sent, :answers

    def initialize
      @sent = []
      @answers = []
      @lock = Mutex.new
    end

    def call(method, path, body: nil, headers: {})
      answer = @lock.synchronize do
        @sent << Sent.new(method, path, headers["Idempotency-Key"], JSON.parse(body)["events"], headers)
        @answers.shift || 202
      end
      raise Errno::ECONNRESET, "keelie down" if answer == :network

      problem = answer >= 400 ? { "type" => "https://keelie.example/problems/usage-out-of-range" } : {}
      Keelie::Response.new(answer, {}, JSON.generate(problem))
    end

    def count = @lock.synchronize { @sent.size }
  end

  # A clock the test moves by hand.
  class Clock
    attr_accessor :now

    def initialize = @now = 1000.0
    def call = @now
  end

  # The lines the SDK logs, while the block runs.
  def capture_log
    lines = []
    lock = Mutex.new
    logger = Object.new
    %i[debug info warn].each do |level|
      logger.define_singleton_method(level) { |message| lock.synchronize { lines << message } }
    end
    Keelie.logger = logger
    yield lines
  ensure
    Keelie.logger = nil
  end

  # Wait until the block is true, or fail after +seconds+.
  def wait_until(seconds = 2)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    until yield
      raise "timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.005
    end
  end

  # Start +app+ on a free port, in Puma.
  def serve(app)
    require "puma"
    require "puma/log_writer"
    server = Puma::Server.new(app, nil, min_threads: 0, max_threads: 8, log_writer: Puma::LogWriter.null)
    server.add_tcp_listener("127.0.0.1", 0)
    server.run
    [server, "http://127.0.0.1:#{server.connected_ports.first}"]
  end

  # One request, written as given, so that the path reaches the server exactly as typed.
  # The status, the headers with lowercase names, and the body.
  def raw(url, method, target, headers = {}, body = nil)
    uri = URI.parse(url)
    TCPSocket.open(uri.host, uri.port) do |socket|
      lines = ["#{method} #{target} HTTP/1.1", "Host: #{uri.host}:#{uri.port}", "Connection: close"]
      headers.each { |name, value| lines << "#{name}: #{value}" }
      lines << "Content-Length: #{body.bytesize}" if body
      socket.write("#{lines.join("\r\n")}\r\n\r\n#{body}")
      response = socket.read
      head, _, rest = response.partition("\r\n\r\n")
      status_line, *header_lines = head.split("\r\n")
      parsed = header_lines.to_h { |line| name, _, value = line.partition(":"); [name.downcase, value.strip] }
      [status_line.split(" ")[1].to_i, parsed, rest]
    end
  end
end
