# frozen_string_literal: true

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
  class HTTP
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
    end

    def initialize(timeout_seconds)
      @timeout = timeout_seconds
    end

    def call(method, url, body: nil, headers: {})
      uri = URI.parse(url)
      raise ArgumentError, "not an http or https URL" unless uri.is_a?(URI::HTTP) && uri.host

      request = Net::HTTPGenericRequest.new(method.to_s.upcase, !body.nil?, method.to_s.upcase != "HEAD",
                                            uri.request_uri, headers)
      request.body = body unless body.nil?
      Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https", open_timeout: @timeout,
                                              read_timeout: @timeout, write_timeout: @timeout) do |http|
        answer = http.request(request)
        Response.new(answer.code.to_i, answer.each_header.to_h, (answer.body || +"").b)
      end
    end
  end
end
