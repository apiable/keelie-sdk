# frozen_string_literal: true

require "openssl"
require "set"

module Keelie
  # The token does not verify. +reason+ is for the log, never for the caller.
  class TokenRejected < StandardError
    # One of +:malformed+, +:algorithm+, +:kid+, +:keys_unavailable+, +:signature+,
    # +:expired+, +:not_yet_valid+, +:issuer+, +:audience+, +:claims+, +:org+ and +:typ+.
    attr_reader :reason

    def initialize(reason)
      super(reason.to_s)
      @reason = reason
    end
  end

  # The claims of a verified token that the SDK reads. Frozen.
  #
  # - +azp+: the client the token was issued to: the credential. +sub+ names the
  #   issuer's own service-account user and is ignored.
  # - +org_id+: your org id, lowercase with hyphens.
  # - +scopes+: a frozen Set of the token's scopes.
  # - +jti+: the token id, or nil.
  # - +expires_at+: when the token expires, from +exp+, a UTC Time. While keelie is
  #   down, the Consumer is served until then, and refused after.
  # - +consumer_id+: on a token for a person, the Consumer whose credits the person
  #   uses, lowercase with hyphens. +azp+ is then the agent's client, which serves
  #   every Consumer. nil on a credential's token, which names its Consumer by +azp+.
  #   Pass it to {UsageReporter#record} with +azp+.
  Claims = Data.define(:azp, :org_id, :scopes, :jti, :expires_at, :consumer_id)

  # Verifies the tokens of one issuer, for one audience and one org, inside your own
  # process.
  #
  # The SDK never asks Apiable whether a token is good. It checks the signature
  # against the issuer's key set (see {SigningKeys}) and the claims against what you
  # configured. The checks run in this order, and the first that fails refuses the
  # token:
  #
  # 1. The token parses, its +alg+ is +RS256+ and it names a +kid+. A token that
  #    says +none+ or +HS256+ is refused before any key is fetched.
  # 2. The key with that +kid+ is in the issuer's key set.
  # 3. The signature, +exp+ (required), +nbf+, +iat+, +iss+ and +aud+.
  # 4. +azp+ names the client, and +org_id+ is your own org id.
  # 5. +typ+ is +Bearer+. An ID token is signed with the same key.
  #
  # The issuer is your own realm: the +issuer+ member of your org in keelie. Each
  # Provider has its own realm, with its own +iss+ and its own key set, so a token of
  # another Provider fails at step 2 or 3. The +org_id+ check stays as a second
  # line: a Provider whose Consumers keelie made before it had a realm shares one
  # issuer and one key set with others, and there +org_id+ tells them apart.
  #
  # Every refusal raises {TokenRejected}. Its +reason+ is for your log, not for the
  # caller: a caller must not learn "expired" from "wrong key".
  #
  # The reasons are the Python SDK's, for the same token. The Python SDK reads the
  # token with PyJWT, so this class reads it by PyJWT's rules, in PyJWT's order.
  class TokenVerifier
    TOKEN_TYPE = "Bearer"
    # Clock skew a token is forgiven.
    LEEWAY_SECONDS = 30
    # The latest +exp+ Python can turn into a date: the end of the year 9999.
    MAX_TIMESTAMP = 253_402_300_799
    # What Python's +str.split()+ splits on.
    WHITESPACE = /[[:space:]\u001c-\u001f]+/
    # A whole number, as Python's +int(str)+ reads it.
    PY_INT = /\A[[:space:]]*[+-]?\d+(?:_\d+)*[[:space:]]*\z/
    # The extensions PyJWT understands in +crit+.
    CRITICAL = ["b64"].freeze

    attr_reader :audience

    # +issuer+ is the +issuer+ member of your org in keelie: your own realm.
    # +audience+ is your API's +resource+ in keelie, exactly. +org_id+ is your org id;
    # a value that is not a UUID raises ArgumentError. +keys+ is the key set: one made
    # from +issuer+ unless you give another.
    def initialize(issuer, audience, org_id, keys: nil, leeway_seconds: LEEWAY_SECONDS)
      @org_id = UUID.parse(org_id.to_s) or raise ArgumentError, "org_id is not a UUID: #{org_id.inspect}"
      @issuer = issuer
      @audience = audience
      @keys = keys || SigningKeys.new(issuer)
      @leeway = leeway_seconds
    end

    # The claims of the token, or {TokenRejected} with the reason.
    def verify(token)
      check(token)
    rescue TokenRejected => e
      Log.info("apiable.token_rejected reason=#{e.reason}")
      raise
    end

    # What the SDK knows of the issuer, from its last fetch of the key set.
    #
    # - +:connected+: the last fetch worked.
    # - +:degraded+: the last fetch failed. The keys in hand go on verifying. The next
    #   fetch that works makes it +:connected+ again.
    # - +:offline+: no key in hand, so every token is refused. A process is +:offline+
    #   until the first token fetches the key set.
    #
    # It makes no network call, and the SDK does not poll. The SDK fetches only on a
    # cold start and for a key it does not know. So while the keys in hand verify
    # every token, an outage of the issuer leaves the status as it is.
    def status = @keys.status

    private

    def reject(reason) = raise(TokenRejected, reason)

    def check(token)
      header, payload_bytes, signing_input, signature = load(token)
      reject(:algorithm) unless header["alg"] == ALGORITHM
      kid = header["kid"]
      reject(:kid) unless kid.is_a?(String) && !kid.empty?

      begin
        key = @keys.key(kid)
      rescue UnknownKey
        reject(:kid)
      rescue KeysUnavailable
        reject(:keys_unavailable)
      end

      # A detached payload (RFC 7797) is never what keelie signs.
      reject(:malformed) if header["b64"] == false
      reject(:signature) unless signed?(key, signature, signing_input)
      begin
        payload = StrictJSON.lenient(payload_bytes)
      rescue JSON::ParserError
        reject(:malformed)
      end
      reject(:malformed) unless payload.is_a?(Hash)

      check_times(payload)
      check_issuer_and_audience(payload)
      claims(payload)
    end

    # The header, the payload's bytes, the signing input and the signature, as
    # PyJWT's +_load+ and +_validate_headers+ read them.
    def load(token)
      reject(:malformed) unless token.is_a?(String)
      token = token.b
      last = token.rindex(".")
      first = token.index(".")
      reject(:malformed) if last.nil? || first == last
      signing_input = token.byteslice(0, last)
      header_segment = token.byteslice(0, first)
      payload_segment = token.byteslice(first + 1, last - first - 1)
      begin
        header = StrictJSON.lenient(Base64URL.decode(header_segment))
        reject(:malformed) unless header.is_a?(Hash)
        if header["b64"] == false
          reject(:malformed) unless payload_segment.empty?
          payload = +""
        else
          payload = Base64URL.decode(payload_segment)
        end
        signature = Base64URL.decode(token.byteslice(last + 1, token.bytesize))
      rescue ArgumentError, JSON::ParserError
        reject(:malformed)
      end
      reject(:malformed) if header.key?("kid") && !header["kid"].is_a?(String)
      check_critical(header) if header.key?("crit")
      [header, payload, signing_input, signature]
    end

    def check_critical(header)
      crit = header["crit"]
      reject(:malformed) unless crit.is_a?(Array) && !crit.empty?
      crit.each do |extension|
        reject(:malformed) unless extension.is_a?(String) && CRITICAL.include?(extension) && header.key?(extension)
      end
    end

    def signed?(key, signature, signing_input)
      key.verify(OpenSSL::Digest.new("SHA256"), signature, signing_input)
    rescue OpenSSL::PKey::PKeyError
      false
    end

    # +exp+ is required. Then +iat+, +nbf+ and +exp+, each when present, in PyJWT's order.
    def check_times(payload)
      reject(:claims) if payload["exp"].nil?
      now = Time.now.to_f
      if payload.key?("iat")
        iat = py_int(payload["iat"])
        reject(:not_yet_valid) if iat.nil? || iat > now + @leeway
      end
      if payload.key?("nbf")
        nbf = py_int(payload["nbf"])
        reject(:malformed) if nbf.nil?
        reject(:not_yet_valid) if nbf > now + @leeway
      end
      exp = py_int(payload["exp"])
      reject(:malformed) if exp.nil?
      reject(:expired) if exp <= now - @leeway
    end

    def check_issuer_and_audience(payload)
      reject(:claims) unless payload.key?("iss")
      reject(:issuer) unless payload["iss"] == @issuer && payload["iss"].is_a?(String)
      aud = payload["aud"]
      reject(:audience) unless py_truthy?(aud)
      aud = [aud] if aud.is_a?(String)
      reject(:audience) unless aud.is_a?(Array) && aud.all?(String) && aud.include?(@audience)
      # PyJWT refuses a +sub+ or a +jti+ that is not a string.
      reject(:malformed) if payload.key?("sub") && !payload["sub"].is_a?(String)
      reject(:malformed) if payload.key?("jti") && !payload["jti"].is_a?(String)
    end

    def claims(payload)
      azp = payload["azp"]
      scope = payload.fetch("scope", "")
      jti = payload["jti"]
      org_id = UUID.parse(payload["org_id"])
      reject(:claims) if org_id.nil?
      reject(:claims) unless azp.is_a?(String) && !azp.empty? && scope.is_a?(String)
      reject(:org) unless org_id == @org_id
      reject(:typ) unless payload["typ"] == TOKEN_TYPE

      exp = payload["exp"]
      reject(:claims) unless exp.is_a?(Integer) || exp.is_a?(Float)
      reject(:claims) if exp > MAX_TIMESTAMP
      consumer = payload["consumer_id"]
      consumer_id = consumer.nil? ? nil : UUID.parse(consumer)
      reject(:claims) if !consumer.nil? && consumer_id.nil?

      Claims.new(
        azp: azp.freeze,
        org_id: org_id.freeze,
        scopes: Set.new(scope.split(WHITESPACE).reject(&:empty?)).freeze,
        jti: jti&.freeze,
        expires_at: Time.at(exp).utc.freeze,
        consumer_id: consumer_id&.freeze
      )
    end

    # The value as Python's +int()+ reads it, or nil where +int()+ fails.
    def py_int(value)
      case value
      when true then 1
      when false then 0
      when Integer then value
      when Float then value.finite? ? value.truncate : nil
      when String then PY_INT.match?(value) ? Integer(value.strip.delete("_"), 10) : nil
      end
    end

    # Python's truth: nil, false, zero and an empty string, list or object are false.
    def py_truthy?(value)
      !(value.nil? || value == false || value == 0 || (value.respond_to?(:empty?) && value.empty?))
    end
  end
end
