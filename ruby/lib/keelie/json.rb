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
    # and only has the option to refuse it from 2.20.0. {strict} refuses it on any release.
    LENIENT = { allow_nan: true }.tap do |options|
      version = Gem::Version.new(JSON::VERSION)
      options[:allow_duplicate_key] = true if version >= Gem::Version.new("2.13.0")
      options[:allow_comments] = false if version >= Gem::Version.new("2.20.0")
    end.freeze

    module_function

    # The value of +text+, read as Python's +json.loads+ reads it. Raises
    # +JSON::ParserError+ for a text that is not JSON.
    def lenient(text)
      JSON.parse(utf8(text), **LENIENT, max_nesting: false)
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
    # refused at its first "/". Each step moves forward or raises.
    def scan(text)
      stack = [] # one entry for each open object or array: [keys or nil, expecting a key]
      bytes = text.b
      i = 0
      length = bytes.bytesize
      while i < length
        c = bytes.getbyte(i)
        if c == 0x22 # a string
          j = string_end(bytes, i)
          top = stack.last
          if top && top[0] && top[1]
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

    # The index of the quote that closes the string opened at +start+. Raises
    # +JSON::ParserError+ if the text ends first, an escape included.
    def string_end(bytes, start)
      j = start + 1
      loop do
        b = bytes.getbyte(j)
        raise JSON::ParserError, "unterminated string" if b.nil?
        return j if b == 0x22

        j += b == 0x5c ? 2 : 1
      end
    end
  end
end
