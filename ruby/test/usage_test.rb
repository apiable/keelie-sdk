# frozen_string_literal: true

require_relative "support"
require "bigdecimal"

class UsageTest < Minitest::Test
  include Support

  def reporter(keelie, **options)
    (@reporters ||= []) << Keelie::UsageReporter.new(keelie, **options)
    @reporters.last
  end

  def teardown
    capture_log { (@reporters || []).each { _1.close(0.5) } }
  end

  def test_sends_a_full_batch_at_once_with_one_key_for_the_batch_and_one_for_each_event
    keelie = FakeKeelie.new
    usage = reporter(keelie, batch_size: 3, flush_interval_seconds: 60)
    usage.record("client-a", "GET /v1/orders/:order_id", credits: 1)
    usage.record("client-a", "GET /v1/orders/:order_id", credits: BigDecimal("0.25"), consumer_id: CONSUMER.upcase)
    usage.record("client-b", "lookup", unit: "tool_call", quantity: 2)
    wait_until { keelie.count == 1 }
    batch = keelie.sent.first
    assert_equal ["POST", "/usage-events:report"], [batch.method, batch.path]
    assert_equal "application/json", batch.headers["Content-Type"]
    assert Keelie::UUID.parse(batch.key)
    first, second, third = batch.events
    assert_equal %w[idempotency_key client_id capability_key unit quantity ts credits], first.keys
    assert_equal ["1", "1", "request"], [first["credits"], first["quantity"], first["unit"]]
    assert_equal ["0.25", CONSUMER], [second["credits"], second["consumer_id"]]
    assert_equal ["tool_call", "2"], [third["unit"], third["quantity"]]
    refute third.key?("credits")
    assert_equal 3, batch.events.map { _1["idempotency_key"] }.uniq.size
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+00:00\z/, first["ts"])
  end

  def test_sends_what_it_holds_at_each_interval
    keelie = FakeKeelie.new
    usage = reporter(keelie, flush_interval_seconds: 0.02)
    usage.record("client-a", "GET /a")
    wait_until { keelie.count == 1 }
    usage.record("client-a", "GET /a")
    wait_until { keelie.count == 2 }
  end

  def test_sends_a_failed_batch_again_with_the_same_key_and_the_same_body
    [401, 408, 409, 429, 500, 503, :network].each do |failure|
      keelie = FakeKeelie.new
      keelie.answers << failure
      capture_log do |lines|
        usage = reporter(keelie, batch_size: 1, flush_interval_seconds: 0.02)
        usage.record("client-a", "GET /a")
        wait_until { keelie.count == 2 }
        assert_equal keelie.sent[0].key, keelie.sent[1].key, failure.inspect
        assert_equal keelie.sent[0].events, keelie.sent[1].events, failure.inspect
        assert(lines.any? { _1.start_with?("apiable.usage_not_sent events=1 ") })
      end
    end
  end

  def test_waits_one_interval_before_a_retry_however_full_the_buffer
    keelie = FakeKeelie.new
    keelie.answers << 503
    capture_log do
      usage = reporter(keelie, batch_size: 1, flush_interval_seconds: 0.3)
      usage.record("client", "first")
      wait_until { keelie.count == 1 }
      5.times { usage.record("client", "more") }
      sleep 0.1
      assert_equal 1, keelie.count
      wait_until { keelie.count >= 2 }
    end
  end

  def test_drops_a_batch_keelie_refuses_and_logs_the_problems_code
    keelie = FakeKeelie.new
    keelie.answers << 400
    capture_log do |lines|
      usage = reporter(keelie, batch_size: 1, flush_interval_seconds: 0.02)
      usage.record("client-a", "GET /a")
      wait_until { keelie.count == 1 }
      usage.record("client-a", "GET /b")
      wait_until { keelie.count == 2 }
      assert_equal "GET /b", keelie.sent[1].events[0]["capability_key"]
      assert_includes lines, "apiable.usage_dropped events=1 status=400 type=usage-out-of-range"
    end
  end

  def test_leaves_out_an_event_keelie_would_refuse_without_raising
    capture_log do |lines|
      usage = reporter(FakeKeelie.new)
      usage.record("", "GET /a")
      usage.record(nil, "GET /a")
      usage.record("client", "x" * 256)
      usage.record("client", "GET /a\n")
      usage.record("client", "\xff".b)
      usage.record("client", "GET /a", unit: "seconds")
      usage.record("client", "GET /a", quantity: 0)
      usage.record("client", "GET /a", quantity: 1.5)
      usage.record("client", "GET /a", credits: -1)
      usage.record("client", "GET /a", outcome_id: "job-1")
      usage.record("client", "GET /a", unit: "outcome", credits: 5)
      usage.record("client", "GET /a", consumer_id: "not-a-uuid")
      assert_equal %w[client_id client_id capability_key capability_key capability_key unit quantity quantity
                      credits outcome_id outcome_id consumer_id].map { "apiable.usage_event_invalid reason=#{_1}" }, lines
    end
  end

  def test_takes_an_outcome_with_no_credits_and_no_id_and_a_unit_given_as_a_symbol
    keelie = FakeKeelie.new
    usage = reporter(keelie, batch_size: 2, flush_interval_seconds: 60)
    usage.record("client", "POST /videos", unit: "outcome", credits: 0)
    usage.record("client", "POST /videos", unit: :tool_call)
    wait_until { keelie.count == 1 }
    assert_equal %w[outcome tool_call], keelie.sent[0].events.map { _1["unit"] }
  end

  def test_keys_an_outcome_as_the_python_sdk_does_so_it_is_charged_once
    keelie = FakeKeelie.new
    usage = reporter(keelie, batch_size: 2, flush_interval_seconds: 60)
    2.times { usage.record("client", "POST /videos", unit: "outcome", credits: 50, outcome_id: "job-42") }
    wait_until { keelie.count == 1 }
    # uuid.uuid5(KEELIE_OUTCOME_NAMESPACE, "job-42") in Python.
    assert_equal ["e13e60df-e85b-588a-a945-f15fed07d021"] * 2, keelie.sent[0].events.map { _1["idempotency_key"] }
  end

  def test_drops_the_oldest_event_when_the_buffer_is_full
    keelie = FakeKeelie.new
    keelie.answers << :network
    capture_log do |lines|
      usage = reporter(keelie, batch_size: 1, max_buffered_events: 2, flush_interval_seconds: 0.05)
      usage.record("client", "first")
      wait_until { keelie.count == 1 } # fails, and is kept to be sent again
      usage.record("client", "second")
      usage.record("client", "third")
      usage.record("client", "fourth")
      wait_until { keelie.count >= 4 }
      assert_equal %w[first first third fourth], keelie.sent.map { _1.events[0]["capability_key"] }
      assert_includes lines, "apiable.usage_dropped events=1 reason=buffer_full"
    end
  end

  def test_sends_what_is_left_on_close_and_records_nothing_after
    keelie = FakeKeelie.new
    usage = reporter(keelie, flush_interval_seconds: 60)
    usage.record("client", "GET /a")
    usage.record("client", "GET /b")
    usage.close
    assert_equal 1, keelie.count
    assert_equal 2, keelie.sent[0].events.size
    usage.record("client", "GET /c")
    usage.close
    usage.start
    assert_equal 1, keelie.count
  end

  def test_gives_up_on_close_after_the_timeout_and_counts_what_is_lost
    never = Object.new
    never.define_singleton_method(:call) { |*, **| sleep }
    capture_log do |lines|
      usage = Keelie::UsageReporter.new(never, flush_interval_seconds: 60)
      usage.record("client", "GET /a")
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      usage.close(0.1)
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
      assert_includes lines, "apiable.usage_dropped events=1 reason=closed"
    end
  end

  def test_a_record_returns_at_once_while_keelie_is_slow
    slow = Object.new
    slow.define_singleton_method(:call) do |*, **|
      sleep 0.5
      Keelie::Response.new(202, {}, "")
    end
    usage = reporter(slow, batch_size: 1, flush_interval_seconds: 60)
    usage.record("client", "GET /a")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    100.times { usage.record("client", "GET /a") }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.1
  end

  def test_starts_again_in_the_child_of_a_fork_with_an_empty_buffer
    skip "no fork here" unless Process.respond_to?(:fork)

    reader, writer = IO.pipe
    keelie = FakeKeelie.new
    usage = reporter(keelie, flush_interval_seconds: 60)
    usage.record("client", "parent")
    pid = fork do
      reader.close
      usage.record("client", "child")
      usage.close(2)
      writer.write(JSON.generate(keelie.sent.map { |sent| sent.events.map { _1["capability_key"] } }))
      writer.close
      exit!(0)
    end
    writer.close
    Process.wait(pid)
    assert_equal [["child"]], JSON.parse(reader.read)
    usage.close
    assert_equal [["parent"]], keelie.sent.map { |sent| sent.events.map { _1["capability_key"] } }
  end

  def test_checks_its_options
    keelie = FakeKeelie.new
    [{ batch_size: 0 }, { batch_size: 1001 }, { flush_interval_seconds: 0 },
     { batch_size: 10, max_buffered_events: 5 }].each do |options|
      assert_raises(ArgumentError, options.inspect) { Keelie::UsageReporter.new(keelie, **options) }
    end
  end

  def test_writes_amounts_as_keelie_reads_them
    {
      1 => "1", BigDecimal("0.25") => "0.25", BigDecimal("1.50") => "1.5", BigDecimal("1.5000000") => "1.5",
      10**9 => "1000000000", BigDecimal("1E+9") => "1000000000", BigDecimal("0.000001") => "0.000001",
      BigDecimal("1E+3") => "1000"
    }.each do |value, text|
      assert_equal text, Keelie::UsageReporter.amount(value, positive: true), value.inspect
    end
    assert_equal "0", Keelie::UsageReporter.amount(0, positive: false)
    assert_equal "0", Keelie::UsageReporter.amount(BigDecimal("0"), positive: false)
  end

  def test_refuses_amounts_where_keelie_would_refuse_them
    [0, -1, BigDecimal("-0"), BigDecimal("NaN"), BigDecimal("Infinity"), BigDecimal("0.0000001"),
     BigDecimal("1000000000.000001"), 10**9 + 1, 1.5, "1", true, nil, Rational(1, 2)].each do |bad|
      assert_nil Keelie::UsageReporter.amount(bad, positive: true), bad.inspect
    end
    assert_nil Keelie::UsageReporter.amount(BigDecimal("-0"), positive: false)
  end

  def test_reads_and_makes_uuids_as_python_does
    canonical = Keelie::KEELIE_OUTCOME_NAMESPACE
    ["{A29FA190-9B27-5A07-A1BA-3A0902A3BDCC}", "urn:uuid:a29fa1909b275a07a1ba3a0902a3bdcc",
     "a29f-a1909b275a07a1ba3a0902a3bdcc"].each do |form|
      assert_equal canonical, Keelie::UUID.parse(form), form
    end
    assert_nil Keelie::UUID.parse("a29fa190")
    assert_nil Keelie::UUID.parse(42)
    # uuid.uuid5 in Python, for the same namespace and names.
    assert_equal "e13e60df-e85b-588a-a945-f15fed07d021", Keelie::UUID.v5(canonical, "job-42")
    assert_equal "ee03fbee-9a39-53c0-af3a-e31f9479559e", Keelie::UUID.v5(canonical, "video/7f3a")
    assert_equal "5fefc917-f063-5bb9-ac54-a2c331480f03", Keelie::UUID.v5(canonical, "ünïcode-outcome")
  end
end
