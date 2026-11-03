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
    LENIENT = { allow_nan: true }.tap do |options|
      options[:allow_duplicate_key] = true if Gem::Version.new(JSON::VERSION) >= Gem::Version.new("2.13.0")
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

    # +text+ is valid JSON here, so the scan only has to track the objects and arrays.
    def scan(text)
      stack = [] # one entry for each open object or array: [keys or nil, expecting a key]
      bytes = text.b
      i = 0
      length = bytes.bytesize
      while i < length
        c = bytes.getbyte(i)
        if c == 0x22 # a string
          j = i + 1
          j += bytes.getbyte(j) == 0x5c ? 2 : 1 until bytes.getbyte(j) == 0x22
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
        end
        i += 1
      end
    end
  end
end
