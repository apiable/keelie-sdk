# frozen_string_literal: true

require "json"
require "securerandom"

module Keelie
  # Collects usage events and sends them to keelie in batches, in a background thread.
  #
  # {#record} puts one event in a buffer in memory and returns. It does no I/O and
  # never waits on the network, so it adds no time to the request that calls it. A
  # background thread sends the buffer to keelie's usage endpoint: when it holds a full
  # batch, and at each interval. The interval is 5 seconds unless you set another.
  #
  # What the SDK reports is telemetry. It feeds the Provider's dashboards and the
  # Consumer's spend cap. Apiable never puts it on an invoice.
  #
  # Each event carries its own idempotency key, and each batch carries an
  # +Idempotency-Key+. A batch that fails on the way is sent again later with the same
  # key and the same body, so keelie keeps each event once.
  #
  # A token for a person names its Consumer in +consumer_id+: its +azp+ is an agent's
  # client, which serves every Consumer. Pass +claims.consumer_id+ to {#record} with
  # each event. keelie then burns that Consumer's credits. On a credential's token it
  # is nil, and nothing is sent.
  #
  # An outcome is charged once. +record(..., unit: "outcome", outcome_id: ...)+ makes
  # the event's key from the outcome ID, with {KEELIE_OUTCOME_NAMESPACE}. The same
  # outcome then has the same key on every repeat, in every process and in every
  # language, and keelie keeps the key in every month. A repeat burns nothing.
  #
  # A report that fails never stops a request:
  #
  # - A network error, a 401, 408, 409, 429 or a 5xx keeps the batch. The thread sends
  #   it again after one interval. It does not read +Retry-After+.
  # - Any other answer drops the batch, with a log line. A retry gets the same answer.
  #   +usage-out-of-range+ is one of these: the batch would take a counter or a balance
  #   past the largest value keelie keeps.
  # - When the buffer is full, the oldest event goes, and a log line counts it.
  #
  # keelie refuses an event older than the start of the previous month. After an
  # outage that long, a batch that holds such an event is dropped.
  #
  # Nothing is written to disk. {#close} sends what is left at shutdown. Events it
  # cannot send in time are lost, with a log line.
  #
  # A process that forks, such as a Puma or Unicorn worker under +preload_app+, gets a
  # new, empty buffer and its own thread in the child, on the child's first {#record}.
  # Events recorded in the parent stay with the parent.
  class UsageReporter
    # The one place that names keelie's usage endpoint.
    PATH = "/usage-events:report"
    UNITS = %w[request tool_call token outcome].freeze
    OUTCOME = "outcome"
    # What keelie takes in one event, and in one batch.
    MAX_NAME_LENGTH = 255
    MAX_AMOUNT = 10**9
    PLACES = 6
    MAX_BATCH_SIZE = 1000
    BATCH_SIZE = 50
    # At most 5 seconds. A Consumer's balance may go below zero for 60 seconds at most,
    # and that window must hold one flush, one failed flush, a retry and a burst.
    FLUSH_INTERVAL_SECONDS = 5.0
    MAX_BUFFERED_EVENTS = 10_000
    CLOSE_TIMEOUT_SECONDS = 10.0
    # The answers that can change on a retry. Every other failure drops the batch. A
    # 401 is one: the credential mints a new token for the next try.
    RETRY_STATUSES = [401, 408, 409, 429].freeze
    CONTROL = /[\x00-\x1f\x7f]/
    PROBLEM_CODE = /\A[a-z0-9-]{1,64}\z/

    # +keelie+ sends a request to keelie with the auth of a credential that may report
    # usage: a {SdkCredential}. Raises ArgumentError when an option is out of range.
    #
    # Make one reporter for the process. The first {#record} starts its thread. Call
    # {#close} when the process shuts down.
    def initialize(keelie, batch_size: BATCH_SIZE, flush_interval_seconds: FLUSH_INTERVAL_SECONDS,
                   max_buffered_events: MAX_BUFFERED_EVENTS)
      unless batch_size.is_a?(Integer) && batch_size.between?(1, MAX_BATCH_SIZE)
        raise ArgumentError, "batch_size must be from 1 to #{MAX_BATCH_SIZE}"
      end
      unless flush_interval_seconds.is_a?(Numeric) && flush_interval_seconds.positive?
        raise ArgumentError, "flush_interval_seconds must be more than 0"
      end
      unless max_buffered_events.is_a?(Integer) && max_buffered_events >= batch_size
        raise ArgumentError, "max_buffered_events must be at least batch_size"
      end

      @keelie = keelie
      @batch_size = batch_size
      @interval = flush_interval_seconds
      @max = max_buffered_events
      @lock = Mutex.new
      @wake = ConditionVariable.new
      @flushing = Mutex.new
      @closed = false
      reset
    end

    # Put one event in the buffer, and return at once.
    #
    # +client_id+ is the +azp+ of the Consumer's token. +capability_key+ names the
    # route or the tool that was called. +unit+ is "request", "tool_call", "token" or
    # "outcome". +quantity+ and +credits+ are an Integer or a BigDecimal, with no sign
    # and at most six decimal places. +credits+ is what the call costs the Consumer's
    # balance; leave it out when the call is free.
    #
    # +outcome_id+ names the outcome of a +unit: "outcome"+ event, such as the ID of the
    # job. It must be unique across all your Consumers. The event's key is made from
    # it, so keelie charges the outcome once, however often it is reported. An outcome
    # with credits needs it. Any other unit must not have it.
    #
    # +consumer_id+ is +claims.consumer_id+: the Consumer of a token for a person, whose
    # credits the call burns. Always pass it. It is nil on a credential's token: keelie
    # refuses a +consumer_id+ there. keelie refuses a batch with an event of an agent's
    # client that has no +consumer_id+.
    #
    # It never raises and never waits. An event keelie would refuse is logged and left
    # out, so it cannot cost the other events of its batch.
    def record(client_id, capability_key, unit: "request", quantity: 1, credits: nil, outcome_id: nil,
               consumer_id: nil)
      return if @closed

      unit = unit.to_s if unit.is_a?(Symbol)
      amount = UsageReporter.amount(quantity, positive: true)
      cost = credits.nil? ? nil : UsageReporter.amount(credits, positive: false)
      consumer = consumer_id.nil? ? nil : UUID.parse(consumer_id)
      reason =
        if !name?(client_id) then "client_id"
        elsif !name?(capability_key) then "capability_key"
        elsif !UNITS.include?(unit) then "unit"
        elsif amount.nil? then "quantity"
        elsif !credits.nil? && cost.nil? then "credits"
        elsif !outcome_id.nil? && (unit != OUTCOME || !name?(outcome_id)) then "outcome_id"
        # Without the ID, each repeat of the outcome would burn the balance again.
        elsif outcome_id.nil? && unit == OUTCOME && cost&.match?(/[1-9]/) then "outcome_id"
        elsif !consumer_id.nil? && consumer.nil? then "consumer_id"
        end
      if reason
        # A fixed word: the value can come from the request, and stays out of the log.
        Log.warn("apiable.usage_event_invalid reason=#{reason}")
        return
      end

      event = {
        "idempotency_key" => outcome_id.nil? ? SecureRandom.uuid : UUID.v5(KEELIE_OUTCOME_NAMESPACE, outcome_id),
        "client_id" => client_id.encode(Encoding::UTF_8),
        "capability_key" => capability_key.encode(Encoding::UTF_8),
        "unit" => unit,
        "quantity" => amount,
        # As Python writes it: microseconds and +00:00.
        "ts" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%6N+00:00")
      }
      event["credits"] = cost unless cost.nil?
      event["consumer_id"] = consumer unless consumer.nil?
      @lock.synchronize do
        reset if @pid != Process.pid
        if @events.size >= @max
          # The oldest event goes to take this one.
          @events.shift
          @dropped += 1
        end
        @events << event
        ensure_thread
        if @events.size >= @batch_size
          @woken = true
          @wake.signal
        end
      end
      nil
    end

    # Start the background thread. {#record} starts it too; this is for a process that
    # wants it running first.
    def start
      @lock.synchronize do
        reset if @pid != Process.pid
        ensure_thread
      end
      nil
    end

    # Stop the background thread, and send what is in the buffer, once.
    #
    # A batch already on its way finishes first. If a batch fails, or +timeout+ seconds
    # pass, what is not sent is dropped, with one log line. It never raises.
    def close(timeout = CLOSE_TIMEOUT_SECONDS)
      thread = @lock.synchronize do
        return if @closed

        @closed = true
        @wake.broadcast
        @pid == Process.pid ? @thread : nil
      end
      deadline = monotonic + timeout
      if thread&.alive?
        thread.kill unless thread.join([deadline - monotonic, 0].max)
      end
      flusher = Thread.new { flush }
      flusher.report_on_exception = false
      flusher.kill unless flusher.join([deadline - monotonic, 0].max)
      lost = @lock.synchronize { @events.size + (@pending ? @pending[2] : 0) }
      Log.warn("apiable.usage_dropped events=#{lost} reason=closed") if lost.positive?
      nil
    end

    # The amount as keelie reads it, a plain decimal String with no sign and at most six
    # places, or nil if keelie would refuse it.
    #
    # @api private
    def self.amount(value, positive:)
      number =
        if value.is_a?(Integer) then value
        elsif defined?(BigDecimal) && value.is_a?(BigDecimal)
          return nil unless value.finite? && value.sign != BigDecimal::SIGN_NEGATIVE_ZERO

          value
        end
      return nil if number.nil? || number.negative? || number > MAX_AMOUNT
      return nil if positive && number.zero?
      return number.to_s if number.is_a?(Integer)
      return nil unless number.round(PLACES) == number

      text = number.to_s("F")
      text.end_with?(".0") ? text.delete_suffix(".0") : text
    end

    private

    # Empty state: on a new reporter, and in the child of a fork, whose parent keeps
    # what it had.
    def reset
      @pid = Process.pid
      @events = []
      # The batch on its way, kept as sent: [key, body, count]. A retry repeats its key
      # and its body.
      @pending = nil
      @dropped = 0
      @woken = false
      @thread = nil
    end

    def ensure_thread
      return if @closed || @thread&.alive?

      @thread = Thread.new { run }
      @thread.name = "keelie-usage"
      @thread.report_on_exception = false
    rescue ThreadError => e
      Log.warn("apiable.usage_flush_failed error=#{e.class.name}")
    end

    def run
      retrying = false
      loop do
        @lock.synchronize do
          @wake.wait(@lock, @interval) unless retrying || @woken || @closed
          @woken = false
        end
        return if @closed

        begin
          retrying = !flush
        rescue StandardError => e
          # The thread must outlive any failure.
          Log.warn("apiable.usage_flush_failed error=#{e.class.name}")
          retrying = true
        end
        # keelie or the network failed. Wait one interval, whatever fills the buffer,
        # then send the same batch again.
        pause if retrying
      end
    end

    def pause
      deadline = monotonic + @interval
      @lock.synchronize do
        until @closed || (left = deadline - monotonic) <= 0
          @wake.wait(@lock, left)
        end
      end
    end

    # Send every batch in the buffer. False if a batch must be sent again later.
    def flush
      @flushing.synchronize do
        loop do
          batch = @lock.synchronize { @pending ||= next_batch }
          return true if batch.nil?
          return false unless deliver(*batch)

          @lock.synchronize { @pending = nil if @pending.equal?(batch) }
        end
      ensure
        log_dropped
      end
    end

    def next_batch
      return nil if @events.empty?

      events = @events.shift(@batch_size)
      [SecureRandom.uuid, JSON.generate({ "events" => events }, ascii_only: true), events.size]
    end

    # Send one batch. True when it is done with: kept by keelie, or dropped.
    def deliver(key, body, count)
      begin
        response = @keelie.call("POST", PATH, body: body,
                                              headers: { "Content-Type" => "application/json", "Idempotency-Key" => key })
      rescue StandardError => e
        # A report never stops the process.
        Log.warn("apiable.usage_not_sent events=#{count} error=#{e.class.name}")
        return false
      end
      status = response.status
      if status.between?(200, 299)
        Log.debug("apiable.usage_sent events=#{count}")
        return true
      end
      if RETRY_STATUSES.include?(status) || status >= 500
        Log.warn("apiable.usage_not_sent events=#{count} status=#{status}")
        return false
      end
      Log.warn("apiable.usage_dropped events=#{count} status=#{status} type=#{problem_type(response.body)}")
      true
    end

    def log_dropped
      dropped = @lock.synchronize { @dropped.tap { @dropped = 0 } }
      Log.warn("apiable.usage_dropped events=#{dropped} reason=buffer_full") if dropped.positive?
    end

    def name?(name)
      return false unless name.is_a?(String)

      text = name.encode(Encoding::UTF_8)
      text.valid_encoding? && text.length.between?(1, MAX_NAME_LENGTH) && !CONTROL.match?(text)
    rescue EncodingError
      false
    end

    # The last segment of the problem's +type+, such as +usage-out-of-range+.
    def problem_type(body)
      problem = StrictJSON.lenient(body.to_s)
      kind = problem["type"] if problem.is_a?(Hash)
      return "unknown" unless kind.is_a?(String)

      code = kind.sub(%r{/+\z}, "").split("/").last.to_s
      # keelie's codes are short and plain. Anything else stays out of the log.
      PROBLEM_CODE.match?(code) ? code : "unknown"
    rescue JSON::ParserError
      "unknown"
    end

    def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # The namespace of an outcome's key: +uuid5(KEELIE_OUTCOME_NAMESPACE, outcome_id)+.
  # Fixed for good, and the same in every language. A UUIDv5 and not a random key: the
  # key must be the same on every repeat of the outcome, so that keelie charges it once.
  KEELIE_OUTCOME_NAMESPACE = "a29fa190-9b27-5a07-a1ba-3a0902a3bdcc"
end
