using System.Diagnostics;

namespace Keelie.Tests;

[Collection("logs")]
public sealed class UsageTests : IAsyncLifetime
{
    private const string ClientId = "consumer-client-1";
    private const string OutOfRange = "https://apiable.io/errors/usage-out-of-range";

    private readonly FakeKeelie _keelie = new();
    private readonly List<UsageReporter> _reporters = [];

    public ValueTask InitializeAsync()
    {
        LogCapture.Clear();
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _keelie.Hold?.TrySetResult();
        foreach (var reporter in _reporters)
        {
            await reporter.CloseAsync(TimeSpan.FromSeconds(1));
        }
    }

    private UsageReporter Reporter(int batchSize = 50, double intervalSeconds = 60, int maxBuffered = 10_000)
    {
        var reporter = new UsageReporter(_keelie.Client(), new UsageReporterOptions
        {
            BatchSize = batchSize,
            FlushInterval = TimeSpan.FromSeconds(intervalSeconds),
            MaxBufferedEvents = maxBuffered,
        });
        _reporters.Add(reporter);
        return reporter;
    }

    [Fact]
    public async Task Record_takes_no_time_while_keelie_does_not_answer()
    {
        _keelie.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reporter = Reporter(batchSize: 2);
        reporter.Record(ClientId, "GET /orders");
        reporter.Record(ClientId, "GET /orders");
        await Wait.UntilAsync(() => _keelie.Requests.Count == 1);

        var started = Stopwatch.StartNew();
        for (var i = 0; i < 100; i++)
        {
            reporter.Record(ClientId, "GET /orders");
        }

        Assert.True(started.Elapsed < TimeSpan.FromMilliseconds(100), started.Elapsed.ToString());
        Assert.Single(_keelie.Requests);
        _keelie.Hold.SetResult();
        await reporter.CloseAsync();
    }

    [Fact]
    public async Task Record_from_many_threads_at_once_loses_nothing()
    {
        var reporter = Reporter(batchSize: 100);
        reporter.Start();

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 250; i++)
            {
                reporter.Record(ClientId, "GET /orders");
            }
        })));
        await reporter.CloseAsync();

        Assert.Equal(2000, _keelie.Batches().Sum(batch => batch.Count));
        Assert.All(_keelie.Batches(), batch => Assert.InRange(batch.Count, 1, 100));
    }

    [Fact]
    public async Task A_full_batch_is_sent_with_its_keys()
    {
        var reporter = Reporter(batchSize: 2);

        reporter.Record(ClientId, "GET /orders", quantity: 3, credits: 0.5m);
        reporter.Record(ClientId, "search", UsageUnit.ToolCall);
        await Wait.UntilAsync(() => _keelie.Requests.Count == 1);

        var request = _keelie.Requests.Single();
        Assert.Equal("POST", request.Method);
        Assert.Equal($"{FakeKeelie.BaseUrl}{UsageReporter.Path}", request.Uri);
        Assert.Equal("application/json", request.Headers["Content-Type"]);
        Assert.True(Guid.TryParse(request.Headers["Idempotency-Key"], out _));
        var events = request.Events;
        var first = events[0];
        var second = events[1];
        Assert.Equal(
            new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
                ["capability_key"] = "GET /orders",
                ["unit"] = "request",
                ["quantity"] = "3",
                ["credits"] = "0.5",
            },
            first.Where(e => e.Key is not ("idempotency_key" or "ts")).ToDictionary());
        Assert.Equal("tool_call", second["unit"]);
        Assert.Equal("1", second["quantity"]);
        Assert.False(second.ContainsKey("credits"));
        Assert.NotEqual(first["idempotency_key"], second["idempotency_key"]);
        Assert.EndsWith("+00:00", first["ts"], StringComparison.Ordinal);
        Assert.True(DateTimeOffset.TryParse(first["ts"], System.Globalization.CultureInfo.InvariantCulture, out _));
        await reporter.CloseAsync();
    }

    [Fact]
    public async Task A_base_address_with_a_path_keeps_its_path()
    {
        using var client = new HttpClient(_keelie, disposeHandler: false) { BaseAddress = new Uri("https://keelie.example.test/api/") };
        var reporter = new UsageReporter(client);

        reporter.Record(ClientId, "GET /orders");
        await reporter.CloseAsync();

        Assert.Equal("https://keelie.example.test/api/usage-events:report", _keelie.Requests.Single().Uri);
    }

    [Fact]
    public async Task A_part_batch_is_sent_at_the_interval()
    {
        var reporter = Reporter(batchSize: 100, intervalSeconds: 0.05);

        reporter.Record(ClientId, "GET /orders");
        Assert.Empty(_keelie.Requests);
        await Wait.UntilAsync(() => _keelie.Requests.Count == 1);

        Assert.Single(_keelie.Batches()[0]);
        await reporter.CloseAsync();
    }

    public static TheoryData<string> Failures() => ["500", "503", "429", "409", "408", "401", "network"];

    [Theory]
    [MemberData(nameof(Failures))]
    public async Task A_failed_batch_is_sent_again_unchanged(string failure)
    {
        _keelie.Answers.Enqueue(failure == "network" ? new HttpRequestException("down") : int.Parse(failure, System.Globalization.CultureInfo.InvariantCulture));
        var reporter = Reporter(batchSize: 1, intervalSeconds: 0.02);

        reporter.Record(ClientId, "GET /orders");
        await Wait.UntilAsync(() => _keelie.Requests.Count == 2);

        var sent = _keelie.Requests.ToArray();
        Assert.Equal(sent[0].Headers["Idempotency-Key"], sent[1].Headers["Idempotency-Key"]);
        Assert.Equal(sent[0].Body, sent[1].Body);
        Assert.Contains("apiable.usage_not_sent", LogCapture.Text, StringComparison.Ordinal);
        await reporter.CloseAsync();
        Assert.Equal(2, _keelie.Requests.Count);
    }

    [Theory]
    [InlineData(422, OutOfRange, "usage-out-of-range")]
    [InlineData(403, null, "unknown")]
    [InlineData(422, "https://apiable.io/errors/x\nfake=line", "unknown")]
    public async Task A_refused_batch_is_dropped_and_never_sent_again(int status, string? problemType, string logged)
    {
        _keelie.Answers.Enqueue(status);
        _keelie.ProblemType = problemType;
        var reporter = Reporter(batchSize: 1, intervalSeconds: 0.02);

        reporter.Record(ClientId, "GET /orders", credits: 1_000_000_000m);
        reporter.Record(ClientId, "GET /orders");
        await Wait.UntilAsync(() => _keelie.Requests.Count == 2);
        await Task.Delay(100);

        var batches = _keelie.Batches();
        Assert.NotEqual(batches[0][0]["idempotency_key"], batches[1][0]["idempotency_key"]);
        Assert.Equal(2, _keelie.Requests.Count);
        Assert.Contains($"apiable.usage_dropped events=1 status={status} type={logged}", LogCapture.Text, StringComparison.Ordinal);
        await reporter.CloseAsync();
    }

    [Fact]
    public async Task A_full_buffer_drops_the_oldest_event()
    {
        var reporter = Reporter(batchSize: 2, maxBuffered: 2);
        _keelie.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        // The first full batch leaves the buffer for keelie, which holds it.
        reporter.Record(ClientId, "first");
        reporter.Record(ClientId, "second");
        await Wait.UntilAsync(() => _keelie.Requests.Count == 1);
        foreach (var name in new[] { "third", "fourth", "fifth" })
        {
            reporter.Record(ClientId, name);
        }
        _keelie.Hold.SetResult();
        await Wait.UntilAsync(() => _keelie.Requests.Count == 2);
        await reporter.CloseAsync();

        var sent = _keelie.Batches().Select(batch => batch.Select(e => e["capability_key"]).ToArray()).ToArray();
        Assert.Equal([["first", "second"], ["fourth", "fifth"]], sent);
        Assert.Contains("apiable.usage_dropped events=1 reason=buffer_full", LogCapture.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Close_sends_what_is_left_and_takes_no_more()
    {
        var reporter = Reporter(batchSize: 2);

        for (var i = 0; i < 3; i++)
        {
            reporter.Record(ClientId, "GET /orders");
        }
        await reporter.CloseAsync();
        reporter.Record(ClientId, "GET /orders");
        await Task.Delay(50);

        Assert.Equal([2, 1], _keelie.Batches().Select(batch => batch.Count));
    }

    public static TheoryData<string> Refused() =>
    [
        "client_id empty",
        "capability_key too long",
        "capability_key with a newline",
        "quantity 0",
        "quantity seven places",
        "unit not defined",
        "credits negative",
        "credits over the maximum",
        // A step that carries the outcome's ID would take its key first.
        "outcome_id on a request",
        // Each repeat of an outcome with no ID would burn the balance again.
        "outcome with credits and no id",
        "outcome_id empty",
    ];

    [Theory]
    [MemberData(nameof(Refused))]
    public async Task An_event_keelie_would_refuse_is_left_out(string name)
    {
        var reporter = Reporter(batchSize: 2);

        switch (name)
        {
            case "client_id empty": reporter.Record("", "GET /orders"); break;
            case "capability_key too long": reporter.Record(ClientId, new string('x', 256)); break;
            case "capability_key with a newline": reporter.Record(ClientId, "GET /orders\n"); break;
            case "quantity 0": reporter.Record(ClientId, "GET /orders", quantity: 0); break;
            case "quantity seven places": reporter.Record(ClientId, "GET /orders", quantity: 0.0000001m); break;
            case "unit not defined": reporter.Record(ClientId, "GET /orders", (UsageUnit)99); break;
            case "credits negative": reporter.Record(ClientId, "GET /orders", credits: -1); break;
            case "credits over the maximum": reporter.Record(ClientId, "GET /orders", credits: 1_000_000_001m); break;
            case "outcome_id on a request": reporter.Record(ClientId, "GET /orders", UsageUnit.Request, outcomeId: "job-1"); break;
            case "outcome with credits and no id": reporter.Record(ClientId, "GET /orders", UsageUnit.Outcome, credits: 10); break;
            case "outcome_id empty": reporter.Record(ClientId, "GET /orders", UsageUnit.Outcome, outcomeId: ""); break;
            default: throw new ArgumentException(name);
        }
        reporter.Record(ClientId, "GET /orders");
        await reporter.CloseAsync();

        Assert.Equal([1], _keelie.Batches().Select(batch => batch.Count));
        Assert.Contains("apiable.usage_event_invalid", LogCapture.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("1", "1")]
    [InlineData("0.5", "0.5")]
    [InlineData("1.500", "1.500")]
    [InlineData("1.0000000", "1.000000")]
    [InlineData("0.000001", "0.000001")]
    [InlineData("1000000000", "1000000000")]
    public void An_amount_is_a_plain_decimal_with_at_most_six_places(string given, string sent)
    {
        Assert.Equal(sent, UsageReporter.FormatAmount(decimal.Parse(given, System.Globalization.CultureInfo.InvariantCulture), positive: true));
    }

    [Fact]
    public async Task Close_gives_up_after_its_timeout()
    {
        _keelie.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reporter = Reporter(batchSize: 2);

        for (var i = 0; i < 3; i++)
        {
            reporter.Record(ClientId, "GET /orders");
        }
        await Wait.UntilAsync(() => _keelie.Requests.Count == 1);
        await reporter.CloseAsync(TimeSpan.FromMilliseconds(50));

        Assert.Contains("apiable.usage_dropped events=3 reason=closed", LogCapture.Text, StringComparison.Ordinal);
    }

    [Theory]
    // The Python SDK's own vectors: uuid.uuid5(KEELIE_OUTCOME_NAMESPACE, name).
    [InlineData("job-42", "e13e60df-e85b-588a-a945-f15fed07d021")]
    [InlineData("video/7f3a", "ee03fbee-9a39-53c0-af3a-e31f9479559e")]
    [InlineData("ünïcode-outcome", "5fefc917-f063-5bb9-ac54-a2c331480f03")]
    public async Task An_outcome_has_the_key_every_sdk_makes_for_it(string outcomeId, string key)
    {
        var reporter = Reporter();

        reporter.Record(ClientId, "POST /videos", UsageUnit.Outcome, credits: 10, outcomeId: outcomeId);
        await reporter.CloseAsync();

        Assert.Equal(key, _keelie.Batches()[0][0]["idempotency_key"]);
    }

    [Fact]
    public async Task One_outcome_has_one_key_in_every_reporter()
    {
        // Two processes report the same outcome: keelie must see one key, and burn once.
        var first = Reporter();
        var second = Reporter();
        foreach (var reporter in new[] { first, second })
        {
            reporter.Record(ClientId, "POST /videos", UsageUnit.Outcome, credits: 10, outcomeId: "job-1");
        }
        first.Record(ClientId, "POST /videos", UsageUnit.Outcome, credits: 10, outcomeId: "job-2");
        // A step before the outcome costs nothing, and needs no ID.
        first.Record(ClientId, "POST /videos", UsageUnit.Outcome, credits: 0);
        await first.CloseAsync();
        await second.CloseAsync();

        var keys = _keelie.Batches().Select(batch => batch.Select(e => e["idempotency_key"]).ToArray()).ToArray();
        Assert.Equal(keys[0][0], keys[1][0]);
        Assert.Single(keys[1]);
        Assert.NotEqual(keys[0][0], keys[0][1]);
        Assert.Equal('4', keys[0][2][14]); // a random UUID, version 4
    }

    [Fact]
    public async Task The_consumer_of_a_token_for_a_person_is_sent_with_the_event()
    {
        var reporter = Reporter(batchSize: 2);
        var consumer = Guid.NewGuid();

        reporter.Record(ClientId, "search", consumerId: consumer);
        reporter.Record(ClientId, "search", consumerId: null);
        await Wait.UntilAsync(() => _keelie.Requests.Count == 1);

        var events = _keelie.Batches()[0];
        Assert.Equal(consumer.ToString(), events[0]["consumer_id"]);
        Assert.False(events[1].ContainsKey("consumer_id"));
        await reporter.CloseAsync();
    }

    [Fact]
    public void The_options_are_checked()
    {
        using var client = _keelie.Client();
        Assert.Throws<ArgumentOutOfRangeException>(() => new UsageReporter(client, new UsageReporterOptions { BatchSize = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UsageReporter(client, new UsageReporterOptions { BatchSize = 1001 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UsageReporter(client, new UsageReporterOptions { FlushInterval = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UsageReporter(client, new UsageReporterOptions { BatchSize = 10, MaxBufferedEvents = 9 }));
        Assert.Throws<ArgumentException>(() => new UsageReporter(new HttpClient()));
    }
}
