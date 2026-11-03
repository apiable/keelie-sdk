# frozen_string_literal: true

require "json"

module Keelie
  # Where an agent looks for the AI Catalog of a domain, and the media type of each
  # path. ARD v0.91 reads +ard.json+ and names no media type for it. The ai-catalog
  # specification reads +ai-catalog.json+, and an MCP proposal points there. Both
  # serve one body. A GET or a HEAD of either needs no token, but only once an
  # {AiCatalog} serves it. This map is the one list of those paths: the guards and the
  # catalog both read it.
  ARD_PATH = "/.well-known/ard.json"
  CATALOG_PATH = "/.well-known/ai-catalog.json"
  CATALOG_MEDIA_TYPES = {
    ARD_PATH => "application/json",
    CATALOG_PATH => "application/ai-catalog+json"
  }.freeze

  # The RFC 9728 metadata of your API, and the challenge that points to it.
  #
  # Two standard pieces, served from your own domain:
  #
  # - The protected resource metadata (RFC 9728). It names your API and the one
  #   issuer that mints tokens for it. An agent reads it at the well-known address of
  #   your API. For +https://api.example.com/mcp+ that is
  #   +https://api.example.com/.well-known/oauth-protected-resource/mcp+.
  # - A 401 with +WWW-Authenticate: Bearer resource_metadata="..."+ on a request that
  #   carries no token (RFC 6750, RFC 9728 section 5). An agent finds the metadata
  #   from this refusal. It does not read the header on a 200.
  #
  # The issuer serves its own authorization server metadata (RFC 8414). The SDK does
  # not copy it: it names the issuer, and the agent reads the issuer.
  class ProtectedResourceMetadata
    WELL_KNOWN = "/.well-known/oauth-protected-resource"

    # Printable ASCII with no space, quote or backslash: the URL goes inside a quoted
    # string of the header, as it is.
    URL_CHARS = /\A[!#-\[\]-~]+\z/

    # The URL an agent types for your API, exactly, path included.
    attr_reader :resource
    # Where the metadata is served on your host, such as
    # +/.well-known/oauth-protected-resource/v1+.
    attr_reader :path
    # The full URL of the metadata, from the configuration, never from the request's Host.
    attr_reader :url
    # The JSON document, as served.
    attr_reader :document
    # @api private The path of +resource+, with no final slash: "" at the root.
    attr_reader :prefix
    # Set by {AiCatalog} when it is made with this metadata. Until then the catalog
    # paths are guarded like any other.
    attr_accessor :ai_catalog

    # +resource+ is your API's address, exactly as registered: https, a lowercase host,
    # no user, query, fragment or final slash. +authorization_server+ is the issuer,
    # the same value you give {TokenVerifier}. It is one issuer: an agent uses the
    # first and does not try a second. +scopes_supported+ is published only if you
    # give it. Raises ArgumentError for a value that breaks these rules.
    def initialize(resource, authorization_server, scopes_supported: nil)
      netloc, resource_path = https_url("resource", resource)
      issuer = https_url("authorization_server", authorization_server) && authorization_server
      @resource = resource.dup.freeze
      # The well-known name goes between the host and the path (RFC 9728 section 3.1).
      @prefix = ["", "/"].include?(resource_path) ? "" : resource_path.sub(%r{/+\z}, "")
      @path = "#{WELL_KNOWN}#{@prefix}".freeze
      @url = "https://#{netloc}#{@path}".freeze
      document = {
        "resource" => @resource,
        "authorization_servers" => [issuer],
        "bearer_methods_supported" => ["header"]
      }
      unless scopes_supported.nil?
        if scopes_supported.is_a?(String)
          raise ArgumentError, "give a list of scopes, not one string: #{scopes_supported.inspect}"
        end

        scopes = scopes_supported.to_a
        raise ArgumentError, "not one scope each: #{scopes.inspect}" unless scopes.all? { ScopeMap.one_scope?(_1) }

        document["scopes_supported"] = scopes
      end
      @document = JSON.generate(document, ascii_only: true).freeze
      @ai_catalog = false
    end

    # The +WWW-Authenticate+ value. Give +"invalid_token"+ for a refused token, and
    # +"insufficient_scope"+ for a token that lacks the scope.
    def challenge(error = nil)
      return %(Bearer resource_metadata="#{@url}") if error.nil?
      raise ArgumentError, "not an RFC 6750 error code: #{error.inspect}" unless /\A[a-z_]+\z/.match?(error.to_s)

      %(Bearer error="#{error}", resource_metadata="#{@url}")
    end

    # True for the path of +resource+ and every path below it.
    def protects?(path)
      @prefix.empty? || path == @prefix || path.start_with?("#{@prefix}/")
    end

    private

    # The host part and the path of +value+, if it is an https URL with a host and no
    # user, query, fragment or final slash.
    #
    # The scheme and the host must be lowercase: an uppercase one is refused, not
    # folded. keelie stores your +resource+ with the same rule and puts it into +aud+
    # exactly, so the value here and the +aud+ of a token compare equal.
    def https_url(name, value)
      raise ArgumentError, "#{name} is not a URL: #{value.inspect}" unless value.is_a?(String) && URL_CHARS.match?(value)

      shape = "#{name} must be https, with a host, no user, query, fragment or final slash: #{value.inspect}"
      raise ArgumentError, shape unless value.match?(%r{\Ahttps://}i) && !value.include?("?") && !value.include?("#")

      rest = value[8..]
      slash = rest.index("/")
      netloc = slash ? rest[0...slash] : rest
      path = slash ? rest[slash..] : ""
      raise ArgumentError, shape if netloc.include?("@")

      if netloc.start_with?("[") # an IPv6 address, then perhaps a port
        close = netloc.index("]") or raise ArgumentError, shape
        host = netloc[0..close]
        after = netloc[(close + 1)..]
        raise ArgumentError, shape unless after.empty? || after.start_with?(":")

        port = after.empty? ? nil : after[1..]
      else
        host, colon, port = netloc.partition(":")
        port = nil if colon.empty?
      end
      raise ArgumentError, shape if host.empty? || host == "[]"
      if port && !port.empty? && !(port.match?(/\A\d+\z/) && port.to_i <= 65_535)
        raise ArgumentError, "#{name} has a port that is not a number: #{value.inspect}"
      end
      raise ArgumentError, shape if !["", "/"].include?(path) && path.end_with?("/")
      unless value.start_with?("https://") && netloc == netloc.downcase
        raise ArgumentError, "#{name} must have a lowercase scheme and host: #{value.inspect}"
      end

      [netloc, path]
    end
  end

  # The Bearer token in an +Authorization+ header value, or nil. The token is not checked.
  def self.bearer_token(authorization)
    return nil unless authorization.is_a?(String)

    scheme, _, token = authorization.strip.partition(" ")
    token = token.strip
    scheme.casecmp?("bearer") && !token.empty? ? token : nil
  end
end
