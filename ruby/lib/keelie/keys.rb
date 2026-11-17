# frozen_string_literal: true

require "openssl"

module Keelie
  # The one algorithm the SDK accepts, in the key set and on the token.
  ALGORITHM = "RS256"

  # No key in the set has this +kid+, after one refresh.
  class UnknownKey < StandardError; end

  # The key set could not be fetched, and no key set is in hand.
  class KeysUnavailable < StandardError; end

  # The issuer's RS256 signing keys, kept in the process.
  #
  # The first token fetches the key set: the issuer's discovery document names its
  # +jwks_uri+, and that document holds the keys. A +kid+ the cache does not know
  # fetches once more, then is refused. That is how a rotated key is picked up
  # without a restart: the first token it signs fetches it.
  #
  # Once a key set is in hand, at most one fetch a minute, however many unknown
  # +kid+ values arrive and whether or not the fetch succeeds. A flood of made-up
  # +kid+ values costs the issuer one request a minute, also while the issuer is
  # down. With no key set in hand, a failed fetch caches nothing, and the next
  # caller tries again.
  #
  # The +jwks_uri+ from the first discovery is kept for the life of the process. A
  # discovery document whose +issuer+ is not the configured one is refused, and no
  # key is fetched from it (OpenID Connect Discovery 1.0, section 4.3). Each
  # Provider has its own realm, so each issuer has its own key set: a document of
  # another realm must never fill this one's.
  #
  # It is safe to share between threads. Every thread that finds the cache cold, or
  # its +kid+ missing, waits on the same fetch.
  class SigningKeys
    # How long the cache refuses a second fetch after one completed. Shorter than any
    # token lifetime, so a rotation is never waited out.
    REFRESH_INTERVAL_SECONDS = 60.0
    FETCH_TIMEOUT_SECONDS = 5.0
    # An RSA key under this many bits is skipped: it verifies nothing.
    MIN_MODULUS_BITS = 2048

    class KeySetError < StandardError; end
    private_constant :KeySetError

    # +http+ is the client the keys are fetched with (see {HTTP}). +clock+ gives
    # seconds from any fixed point.
    def initialize(issuer, http: nil, clock: nil, refresh_interval_seconds: REFRESH_INTERVAL_SECONDS)
      @issuer = issuer.sub(%r{/+\z}, "")
      @http = http || HTTP.for(FETCH_TIMEOUT_SECONDS)
      @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      @interval = refresh_interval_seconds
      @keys = {}.freeze
      @jwks_uri = nil
      @fetched_at = nil
      @refresh_failed = false
      @lock = Mutex.new
    end

    # The key with this id, fetching the set once if it is not there. Raises
    # {UnknownKey} or {KeysUnavailable}.
    def key(kid)
      known = @keys[kid]
      return known if known

      @lock.synchronize do
        refresh if !@keys.key?(kid) && may_fetch?
      end
      @keys[kid] or raise UnknownKey, "unknown kid"
    end

    # +:offline+ with no key, +:degraded+ if the last fetch failed, else +:connected+.
    def status
      return :offline if @keys.empty?

      @refresh_failed ? :degraded : :connected
    end

    private

    def may_fetch?
      @fetched_at.nil? || @clock.call - @fetched_at >= @interval
    end

    def refresh
      begin
        keys = signing_keys(fetch)
      rescue StandardError => e
        if @fetched_at.nil?
          # Cold: nothing to verify with. Nothing is cached, so the next caller tries again.
          Log.warn("apiable.keys_unavailable: #{e.class.name}")
          raise KeysUnavailable, e.class.name
        end
        # Warm: the keys in hand go on verifying, and the issuer is not asked again
        # for another interval.
        @fetched_at = @clock.call
        @refresh_failed = true
        Log.warn("apiable.keys_not_refreshed: #{e.class.name}")
        return
      end
      @keys = keys.freeze
      @fetched_at = @clock.call
      @refresh_failed = false
      Log.info("apiable.keys_loaded kids=#{keys.keys.sort.inspect}")
    end

    def fetch
      jwks_uri = @jwks_uri
      if jwks_uri.nil?
        document = get_json("#{@issuer}/.well-known/openid-configuration")
        issuer = member(document, "issuer")
        raise KeySetError, "issuer" unless issuer.is_a?(String) && issuer.sub(%r{/+\z}, "") == @issuer

        jwks_uri = member(document, "jwks_uri")
        raise KeySetError, "jwks_uri" unless jwks_uri.is_a?(String)
      end
      key_set = member(get_json(jwks_uri), "keys")
      @jwks_uri = jwks_uri
      key_set
    end

    def get_json(url)
      response = @http.call("GET", url)
      raise KeySetError, "status #{response.status}" unless response.status.between?(200, 299)

      StrictJSON.lenient(response.body)
    end

    def member(document, name)
      raise KeySetError, "document" unless document.is_a?(Hash)
      raise KeySetError, name unless document.key?(name)

      document[name]
    end

    def signing_keys(key_set)
      raise KeySetError, "keys" unless key_set.is_a?(Array)

      keys = {}
      key_set.each do |jwk|
        # The issuer can publish an encryption key beside the signing key. Only an RSA
        # key for signing, with the one algorithm and a kid, verifies a token.
        next unless jwk.is_a?(Hash) && jwk["kid"].is_a?(String) && jwk["kty"] == "RSA" &&
                    [nil, "sig"].include?(jwk["use"]) && [nil, ALGORITHM].include?(jwk["alg"])

        begin
          keys[jwk["kid"]] = public_key(jwk["n"], jwk["e"])
        rescue StandardError
          # A key the SDK cannot load is skipped. The rest of the set loads.
          Log.warn("apiable.key_skipped kid=#{jwk["kid"]}")
        end
      end
      keys
    end

    # The public members only: a private member published by mistake is never loaded.
    def public_key(n, e)
      modulus = OpenSSL::BN.new(Base64URL.decode_member(n), 2)
      exponent = OpenSSL::BN.new(Base64URL.decode_member(e), 2)
      raise KeySetError, "modulus" if modulus.num_bits < MIN_MODULUS_BITS || !modulus.odd?
      raise KeySetError, "exponent" if exponent < 3 || !exponent.odd? || exponent >= modulus

      rsa = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(modulus), OpenSSL::ASN1::Integer(exponent)])
      der = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)]),
        OpenSSL::ASN1::BitString(rsa.to_der)
      ])
      OpenSSL::PKey::RSA.new(der.to_der)
    end
  end

  # Base64url, read strictly as PyJWT reads a token's segments.
  #
  # @api private
  module Base64URL
    ALPHABET = /\A[A-Za-z0-9_-]*\z/

    module_function

    # The bytes of +segment+, or ArgumentError. Up to two "=" of padding are allowed,
    # on a segment whose length is then a multiple of four. Every other character must
    # be in the URL-safe alphabet, and the text must be the one canonical encoding of
    # its bytes.
    def decode(segment)
      raise ArgumentError, "not a string" unless segment.is_a?(String)

      stripped = segment.b
      padding = 0
      while stripped.end_with?("=")
        stripped = stripped.byteslice(0, stripped.bytesize - 1)
        padding += 1
        raise ArgumentError, "padding" if padding > 2
      end
      raise ArgumentError, "padding" if padding.positive? && (segment.bytesize % 4).nonzero?
      raise ArgumentError, "alphabet" if stripped.bytesize % 4 == 1 || !ALPHABET.match?(stripped)

      standard = stripped.tr("-_", "+/")
      standard += "=" * ((4 - (standard.bytesize % 4)) % 4)
      bytes = standard.unpack1("m0")
      raise ArgumentError, "not canonical" unless encode(bytes) == stripped

      bytes
    end

    # The bytes of a key's member, read as PyJWT reads it: padding and characters
    # outside the alphabet are passed over.
    def decode_member(value)
      raise ArgumentError, "not a string" unless value.is_a?(String)

      standard = value.b.delete("=").tr("-_", "+/")
      standard += "=" * ((4 - (standard.bytesize % 4)) % 4)
      standard.unpack1("m")
    end

    def encode(bytes)
      [bytes].pack("m0").tr("+/", "-_").delete("=")
    end
  end
end
