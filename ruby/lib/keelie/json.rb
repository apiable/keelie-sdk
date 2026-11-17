# frozen_string_literal: true

require "json"

module Keelie
  # JSON as the Python SDK reads it.
  #
  # @api private
  module StrictJSON
    # Deeper than this is refused, as Python's parser refuses it at its recursion limit.
    MAX_DEPTH = 1000

    class DuplicateKey < StandardError; end

    # Python's json module reads NaN and Infinity, and keeps the last value of a key
    # given twice. The json gem's newest releases warn on a key given twice, or refuse
    # it, unless they are told not to.
    # Python's parser refuses a comment; the json gem reads one by default before 3.0
    # and only has the option to refuse it from 2.20.0. {strict} and {lenient} refuse it on
    # any release, by their scan.
    LENIENT = { allow_nan: true }.tap do |options|
      version = Gem::Version.new(JSON::VERSION)
      options[:allow_duplicate_key] = true if version >= Gem::Version.new("2.13.0")
      options[:allow_comments] = false if version >= Gem::Version.new("2.20.0")
    end.freeze

    module_function

    # The value of +text+, bytes read as Python's +json.loads+ reads bytes. Raises
    # +JSON::ParserError+ for a text that is not JSON, or is nested deeper than
    # {MAX_DEPTH}. PyJWT and httpx hand +json.loads+ bytes, so it reads a UTF-16 or
    # UTF-32 text, and one UTF-8 byte order mark, as Python's +json.detect_encoding+ does.
    #
    # The token's header is read with it before the signature is checked, so the caller
    # writes the text. json gems before 2.10, such as the 2.6.3 that ships with Ruby
    # 3.2, read arrays by recursion: with no limit, a deep text overflows the stack, and
    # +SystemStackError+ is no +JSON::ParserError+. Python refuses a deep text too, as
    # PyJWT's +DecodeError+, at its recursion limit.
    #
    # One difference is known: Python reads a lone surrogate, as UTF-8 bytes, in
    # UTF-16 or as an escape such as "\ud800". Ruby refuses it. Such a token is
    # +:malformed+ in Ruby: refused, where Python may give another reason.
    def lenient(text)
      text = utf8(python_decode(text.b))
      # The gem's own limit is off by one in some releases. The scan counts exactly,
      # and refuses what older gems read and Python does not: a comment, an unknown
      # escape, a control character in a string.
      value = JSON.parse(text, **LENIENT, max_nesting: MAX_DEPTH + 2)
      scan(text, keys: false)
      value
    end

    BOMS = {
      "\x00\x00\xFE\xFF".b => "UTF-32", "\xFF\xFE\x00\x00".b => "UTF-32",
      "\xFE\xFF".b => "UTF-16", "\xFF\xFE".b => "UTF-16"
    }.freeze
    private_constant :BOMS

    # +bytes+ as UTF-8, decoded as Python's +json.loads+ decodes bytes.
    def python_decode(bytes)
      return bytes.byteslice(3..) if bytes.start_with?("\xEF\xBB\xBF".b)

      encoding = BOMS.find { |bom, _| bytes.start_with?(bom) }&.last || zero_bytes_encoding(bytes)
      return bytes if encoding.nil?

      bytes.dup.force_encoding(encoding).encode(Encoding::UTF_8)
    rescue EncodingError
      raise JSON::ParserError, "not #{encoding}"
    end

    # The encoding Python reads from the zero bytes at the start of a text with no byte
    # order mark, or nil for UTF-8.
    def zero_bytes_encoding(bytes)
      b0, b1, b2, b3 = bytes.byteslice(0, 4).bytes
      if bytes.bytesize >= 4
        return b1.zero? ? "UTF-32BE" : "UTF-16BE" if b0.zero?
        return b2.zero? && b3.zero? ? "UTF-32LE" : "UTF-16LE" if b1.zero?
      elsif bytes.bytesize == 2
        return "UTF-16BE" if b0.zero?
        return "UTF-16LE" if b1.zero?
      end
      nil
    end

    # The value of +text+. Raises {DuplicateKey} for a key given twice in one object,
    # and +JSON::ParserError+ for a text that is not UTF-8 JSON or is nested deeper
    # than {MAX_DEPTH}.
    #
    # Two parsers can pick different values for a key given twice. A guard that read
    # one tool name while your server read another would check the wrong scope. Keys
    # compare after their escapes are read: "a" and "a" are the same key.
    def strict(text)
      text = utf8(text)
      # The gem's own limit is off by one in some releases. The scan counts exactly.
      value = JSON.parse(text, **LENIENT, max_nesting: MAX_DEPTH + 2)
      scan(text)
      value
    end

    def utf8(text)
      text = text.b.force_encoding(Encoding::UTF_8)
      # Python's json module refuses a text that is not UTF-8, and a byte order mark.
      raise JSON::ParserError, "not UTF-8" unless text.valid_encoding?
      raise JSON::ParserError, "byte order mark" if text.start_with?("\uFEFF")

      text
    end

    # The bytes that may stand outside a string in JSON: whitespace, the six structural
    # characters, the characters of a number, and the letters of true, false, null, NaN
    # and Infinity.
    OUTSIDE = (" \t\n\r{}[],:0123456789+-.eE" + ("a".."z").to_a.join + ("A".."Z").to_a.join).bytes.freeze
    private_constant :OUTSIDE

    # +text+ has been parsed, so the scan only has to track the objects and arrays. It
    # refuses any byte outside a string that JSON does not allow there, so it never reads
    # a text the parser read some other way: a comment, which older json gems read, is
    # refused at its first "/". Each step moves forward or raises. With +keys: false+,
    # a key given twice passes.
    def scan(text, keys: true)
      stack = [] # one entry for each open object or array: [keys or nil, expecting a key]
      bytes = text.b
      i = 0
      length = bytes.bytesize
      while i < length
        c = bytes.getbyte(i)
        if c == 0x22 # a string
          j = string_end(bytes, i)
          top = stack.last
          if keys && top && top[0] && top[1]
            literal = bytes.byteslice(i, j - i + 1).force_encoding(Encoding::UTF_8)
            key = JSON.parse("[#{literal}]").first
            raise DuplicateKey if top[0].key?(key)

            top[0][key] = true
            top[1] = false
          end
          i = j
        elsif c == 0x7b || c == 0x5b # { [
          stack << (c == 0x7b ? [{}, true] : [nil, false])
          raise JSON::NestingError, "nested too deeply" if stack.size > MAX_DEPTH
        elsif c == 0x7d || c == 0x5d # } ]
          stack.pop
        elsif c == 0x2c # ,
          top = stack.last
          top[1] = true if top && top[0]
        elsif !OUTSIDE.include?(c)
          raise JSON::ParserError, "unexpected byte outside a string"
        end
        i += 1
      end
    end

    # The bytes that may follow a backslash in a string: " \\ / b f n r t u.
    ESCAPES = '"\\/bfnrtu'.bytes.freeze
    HEX = "0123456789abcdefABCDEF".bytes.freeze
    private_constant :ESCAPES, :HEX

    # The index of the quote that closes the string opened at +start+. Raises
    # +JSON::ParserError+ if the text ends first, for a control character, and for an
    # escape Python does not read: json 2.6.3 reads "\x" as "x".
    def string_end(bytes, start)
      j = start + 1
      loop do
        b = bytes.getbyte(j)
        raise JSON::ParserError, "unterminated string" if b.nil?
        return j if b == 0x22
        raise JSON::ParserError, "control character in a string" if b < 0x20

        if b == 0x5c
          e = bytes.getbyte(j + 1)
          raise JSON::ParserError, "invalid escape" unless e && ESCAPES.include?(e)
          if e == 0x75 # u
            hex = bytes.byteslice(j + 2, 4).to_s.bytes
            raise JSON::ParserError, "invalid escape" unless hex.size == 4 && hex.all? { HEX.include?(_1) }

            j += 4
          end
          j += 2
        else
          j += 1
        end
      end
    end
  end
end
