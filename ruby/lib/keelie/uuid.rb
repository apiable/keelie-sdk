# frozen_string_literal: true

require "digest"

module Keelie
  # The UUID rules the Python SDK gets from its standard library.
  #
  # {parse} reads a UUID as Python's +uuid.UUID(str)+ does, so the two SDKs accept
  # and refuse the same values. {v5} makes the same key from the same namespace and
  # name as Python's +uuid.uuid5+.
  #
  # @api private
  module UUID
    HEX = /\A[0-9a-fA-F]{32}\z/

    module_function

    # The UUID in its canonical form, lowercase with hyphens, or nil if it is not one.
    def parse(value)
      return nil unless value.is_a?(String) && value.valid_encoding?

      # Python's order: drop "urn:" and "uuid:", the braces, then every hyphen.
      hex = value.gsub("urn:", "").gsub("uuid:", "")
      hex = hex.gsub(/\A[{}]+|[{}]+\z/, "").delete("-")
      return nil unless HEX.match?(hex)

      format(hex.downcase)
    end

    # The name-based UUID of RFC 9562, version 5 (SHA-1).
    def v5(namespace, name)
      ns = parse(namespace) or raise ArgumentError, "namespace is not a UUID"
      digest = Digest::SHA1.digest([ns.delete("-")].pack("H*") + name.encode(Encoding::UTF_8).b).bytes
      digest[6] = (digest[6] & 0x0f) | 0x50
      digest[8] = (digest[8] & 0x3f) | 0x80
      format(digest[0, 16].pack("C*").unpack1("H*"))
    end

    def format(hex)
      "#{hex[0, 8]}-#{hex[8, 4]}-#{hex[12, 4]}-#{hex[16, 4]}-#{hex[20, 12]}"
    end
  end
end
