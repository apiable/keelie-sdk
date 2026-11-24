# frozen_string_literal: true

require "delegate"
require "net/http"
require "uri"

module Keelie
  # The answer to one HTTP request: the status, the headers with lowercase names, and
  # the body as a binary String.
  Response = Struct.new(:status, :headers, :body) do
    def success? = status.between?(200, 299)
  end

  # The SDK's HTTP client: one request at a time, with Net::HTTP.
  #
  # Every client the SDK uses, here or one you give, answers
  # +call(method, url, body: nil, headers: {})+ with a {Response}, and raises for a
  # network error. A test gives its own client, which answers without a network.
  # {HTTP.default} is the client the SDK uses where you give none.
  #
  # The timeout is for the whole request: connect, send and the full answer. A server
  # that sends its answer one byte at a time is cut off when the time is up. The client
  # sends to https only, or to plain http on a loopback host, for local development.
  class HTTP
    # The hosts that take plain http: the machine itself, for local development.
    LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"].freeze

    class << self
      # The client for the SDK objects made without one, given the timeout they ask
      # for. nil (the default) makes a {HTTP}. A test can set a callable here, such as
      # +->(timeout) { fake }+, to keep every SDK object it does not build itself off the
      # network.
      attr_accessor :default

      # @api private
      def for(timeout_seconds)
        default ? default.call(timeout_seconds) : new(timeout_seconds)
      end

      # @api private
      # True for an https URL with a host, and for a plain http URL on a loopback host. A
      # URL with a user part, such as +https://user@host+, is refused.
      def secure_url?(url)
        uri = URI.parse(url)
        return false unless uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty? && uri.userinfo.nil?

        uri.scheme.casecmp?("https") || LOOPBACK_HOSTS.include?(uri.host.downcase)
      rescue URI::Error, TypeError
        false
      end

      # @api private
      # +url+, or ArgumentError when it is not a secure URL. +name+ names it in the error.
      def secure_url!(name, url)
        return url if url.is_a?(String) && secure_url?(url)

        raise ArgumentError, "#{name} must be https with no user part (plain http only on localhost, " \
                             "127.0.0.1 or [::1]): #{url.inspect}"
      end

      # @api private
      def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # @api private
      # The seconds left before +deadline+, or +error+ if none are left.
      def left(deadline, error)
        left = deadline - monotonic
        raise error unless left.positive?

        left
      end
    end

    def initialize(timeout_seconds)
      @timeout = timeout_seconds
    end

    def call(method, url, body: nil, headers: {})
      uri = URI.parse(url)
      raise ArgumentError, "not an http or https URL" unless uri.is_a?(URI::HTTP) && uri.host
      raise ArgumentError, "plain http is for a loopback host only" unless HTTP.secure_url?(url)

      deadline = HTTP.monotonic + @timeout
      request = Net::HTTPGenericRequest.new(method.to_s.upcase, !body.nil?, method.to_s.upcase != "HEAD",
                                            uri.request_uri, headers)
      request.body = body unless body.nil?
      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = uri.scheme.casecmp?("https")
      http.open_timeout = http.read_timeout = http.write_timeout = @timeout
      # A retry would start again on a clock that has already run.
      http.max_retries = 0
      http.extend(Deadline)
      http.keelie_deadline = deadline
      http.start do
        answer = http.request(request)
        Response.new(answer.code.to_i, answer.each_header.to_h, (answer.body || +"").b)
      end
    end

    # Net::HTTP with one deadline for the whole request. Net::HTTP's own read timeout
    # bounds each wait for a read, not the answer: a server that sends a byte now and
    # then holds the call for as long as it likes. Here each wait, each read and each
    # write is bounded by the time left. The SDK adds no Timeout of its own. Net::HTTP
    # can still use Timeout for the TCP open, on a Ruby whose TCPSocket has no
    # +open_timeout+.
    module Deadline
      attr_accessor :keelie_deadline

      private

      def connect
        # Each step of the connect waits the time left at most: the TCP open, and the
        # CONNECT exchange with a proxy from the environment (+http_proxy+), which
        # Net::HTTP reads before the socket below is wrapped.
        left = HTTP.left(keelie_deadline, Net::OpenTimeout)
        @open_timeout = @read_timeout = @write_timeout = left
        super
        # Net::BufferedIO keeps the socket in @io. Every read, write and wait of the
        # request goes through it from here on.
        @socket.instance_variable_set(:@io, DeadlineSocket.new(@socket.io, keelie_deadline))
      end

      # Where Net::HTTP opens the TCP socket in a method of its own (net-http 0.5 and
      # later), the socket itself gets the deadline. A proxy's CONNECT answer is read
      # from it, so a proxy that sends a byte now and then is cut off in time too. An
      # older net-http bounds each wait of that exchange by the time left only.
      if Net::HTTP.private_method_defined?(:timeouted_connect)
        def timeouted_connect(*)
          socket = super
          socket.extend(SocketDeadline)
          socket.keelie_deadline = keelie_deadline
          socket
        end
      end

      # The TLS handshake waits the time left, not a second full timeout.
      def ssl_socket_connect(socket, _timeout)
        super(socket, HTTP.left(keelie_deadline, Net::OpenTimeout))
      end
    end

    # The TCP socket of a request, with a deadline on each read, write and wait. It is
    # the socket object itself, so TLS still runs on it.
    module SocketDeadline
      attr_accessor :keelie_deadline

      def read_nonblock(*args, **options)
        HTTP.left(keelie_deadline, Net::ReadTimeout)
        super
      end

      def write_nonblock(*args, **options)
        HTTP.left(keelie_deadline, Net::WriteTimeout)
        super
      end

      def wait_readable(_timeout = nil) = super([keelie_deadline - HTTP.monotonic, 0].max)
      def wait_writable(_timeout = nil) = super([keelie_deadline - HTTP.monotonic, 0].max)
    end

    # The socket of a request, with a deadline on each read, write and wait.
    class DeadlineSocket < SimpleDelegator
      def initialize(socket, deadline)
        super(socket)
        @deadline = deadline
      end

      def read_nonblock(*args, **options)
        HTTP.left(@deadline, Net::ReadTimeout)
        __getobj__.read_nonblock(*args, **options)
      end

      def write_nonblock(*args, **options)
        HTTP.left(@deadline, Net::WriteTimeout)
        __getobj__.write_nonblock(*args, **options)
      end

      def to_io = Waits.new(__getobj__.to_io, @deadline)
    end

    # The IO a Net::BufferedIO waits on. Each wait lasts the time left at most. When no
    # time is left, the wait answers "not ready" at once, and Net::HTTP raises its own
    # timeout.
    class Waits < SimpleDelegator
      def initialize(io, deadline)
        super(io)
        @deadline = deadline
      end

      def wait_readable(_timeout = nil) = __getobj__.wait_readable(time_left)
      def wait_writable(_timeout = nil) = __getobj__.wait_writable(time_left)

      private

      def time_left = [@deadline - HTTP.monotonic, 0].max
    end
    private_constant :Deadline, :SocketDeadline, :DeadlineSocket, :Waits
  end
end
