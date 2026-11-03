# frozen_string_literal: true

module Keelie
  # Where the SDK writes its log lines.
  #
  # Each line is one fixed event name and its fields, such as
  # +apiable.token_rejected reason=expired+. The names are the Python SDK's, so one
  # search finds an event in both. No line holds a token, a secret or a value taken
  # from the request.
  #
  # By default +warn+ goes to standard error, and +info+ and +debug+ are dropped.
  # Give your own logger with {Keelie.logger=}: a stdlib +Logger+, +Rails.logger+
  # and anything else with +debug+, +info+ and +warn+ fit.
  module Log
    # The default: warnings to standard error, the rest dropped.
    module Quiet
      def self.debug(_message) = nil
      def self.info(_message) = nil
      def self.warn(message) = Kernel.warn(message)
    end

    @logger = Quiet

    class << self
      attr_reader :logger

      def logger=(logger)
        @logger = logger || Quiet
      end

      def debug(message) = @logger.debug(message)
      def info(message) = @logger.info(message)
      def warn(message) = @logger.warn(message)
    end
  end

  class << self
    # The logger the SDK writes to. {Log::Quiet} unless you set another.
    def logger = Log.logger

    # Send the SDK's log lines to +logger+. Give +nil+ for the default.
    def logger=(logger)
      Log.logger = logger
    end
  end
end
