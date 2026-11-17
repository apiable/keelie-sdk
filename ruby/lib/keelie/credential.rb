# frozen_string_literal: true

require "json"
require "uri"

module Keelie
  # Talk to keelie with your SDK credential.
  #
  # The usage reporter and the AI Catalog call keelie's API. Each call carries a token
  # of the +sdk_credential+ from your signup: it may report usage and read your
  # products, and nothing else. This class mints that token at your issuer with the
  # client credentials grant, keeps it until shortly before it expires, and mints again
  # on a 401. Threads that find the token stale wait on one mint.
  #
  # The SDK holds no secret of its own. Read the client id and the secret from the
  # environment, never from source code. Never give it your admin credential.
  #
  # It answers +call(method, path, body: nil, headers: {})+ with a {Response}, where
  # +path+ is keelie's path, such as +/usage-events:report+. That is all
  # {UsageReporter} and {AiCatalog} need from it: a test gives them its own object
  # with that method.
  class SdkCredential
    TIMEOUT_SECONDS = 10

    # +keelie_url+ is the address of keelie (+KEELIE_URL+), +token_url+ the token
    # endpoint of keelie's issuer (+KEELIE_TOKEN_URL+), and +client_id+ and
    # +client_secret+ the +sdk_credential+ from the signup answer. +timeout_seconds+ is
    # how long a call to keelie, or to the token endpoint, waits.
    def initialize(keelie_url:, token_url:, client_id:, client_secret:, timeout_seconds: TIMEOUT_SECONDS,
                   http: nil, clock: nil)
      @base = keelie_url.sub(%r{/+\z}, "")
      @token_url = token_url
      @http = http || HTTP.for(timeout_seconds)
      @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      @form = URI.encode_www_form(grant_type: "client_credentials", client_id: client_id,
                                  client_secret: client_secret).freeze
      @token = nil
      @expires_at = 0.0
      @lock = Mutex.new
    end

    # Send one request to keelie, with a token of the credential. Raises for a network
    # error, and when the token endpoint refuses the credential.
    def call(method, path, body: nil, headers: {})
      token = fresh_token(nil)
      response = send_with(token, method, path, body, headers)
      return response unless response.status == 401

      send_with(fresh_token(token), method, path, body, headers)
    end

    def inspect = "#<#{self.class.name} #{@base}>"

    private

    def send_with(token, method, path, body, headers)
      @http.call(method, "#{@base}#{path}", body: body, headers: headers.merge("Authorization" => "Bearer #{token}"))
    end

    # The token to send. +refused+ is a token keelie answered 401: mint again, unless
    # another thread already has.
    def fresh_token(refused)
      @lock.synchronize do
        mint if @token.nil? || @clock.call >= @expires_at || (refused && @token == refused)
        @token
      end
    end

    def mint
      response = @http.call("POST", @token_url, body: @form,
                                                headers: { "Content-Type" => "application/x-www-form-urlencoded" })
      raise Error, "the token endpoint answered #{response.status}" unless response.success?

      body = StrictJSON.lenient(response.body)
      token = body["access_token"] if body.is_a?(Hash)
      lifetime = body["expires_in"] if body.is_a?(Hash)
      unless token.is_a?(String) && lifetime.is_a?(Numeric)
        raise Error, "the token endpoint answered without a token"
      end

      @token = token
      # Mint again before the token expires.
      @expires_at = @clock.call + [lifetime - 30, lifetime / 2.0].max
    end
  end
end
