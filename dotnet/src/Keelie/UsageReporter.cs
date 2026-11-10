using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Keelie;

/// <summary>What a usage event counts.</summary>
public enum UsageUnit
{
    /// <summary>One call of a route. Sent as <c>request</c>.</summary>
    Request,

    /// <summary>One call of an MCP tool. Sent as <c>tool_call</c>.</summary>
    ToolCall,

    /// <summary>Tokens, such as of a model. Sent as <c>token</c>.</summary>
    Token,

    /// <summary>One outcome, such as a finished job. Sent as <c>outcome</c>.</summary>
    Outcome,
}

/// <summary>Options of <see cref="UsageReporter"/>.</summary>
public sealed class UsageReporterOptions
{
    /// <summary>Events in one batch, from 1 to 1000. A full batch is sent at once. 50.</summary>
    public int BatchSize { get; init; } = UsageReporter.DefaultBatchSize;

    /// <summary>The reporter sends what waits at least this often. Keep it at 5 seconds or less. 5 seconds.</summary>
    public TimeSpan FlushInterval { get; init; } = UsageReporter.DefaultFlushInterval;

    /// <summary>When the buffer is full, the oldest event goes, with a log line. 10,000.</summary>
    public int MaxBufferedEvents { get; init; } = UsageReporter.DefaultMaxBufferedEvents;
}

/// <summary>
/// Collects usage events and sends them to keelie in batches, in the background.
/// </summary>
/// <remarks>
/// <see cref="Record"/> puts one event in a buffer in memory and returns. It does no I/O and never
/// waits on the network, so it adds no time to the request that calls it. A background task sends
/// the buffer to keelie's usage endpoint: when it holds a full batch, and at each interval.
/// <para>
/// What the SDK reports is telemetry. It feeds the Provider's dashboards and the Consumer's spend
/// cap. Apiable never puts it on an invoice.
/// </para>
/// <para>
/// Each event carries its own idempotency key, and each batch carries an <c>Idempotency-Key</c>. A
/// batch that fails on the way is sent again later with the same key and the same body, so keelie
/// keeps each event once. An outcome's key is made from its outcome ID, so the same outcome has the
/// same key on every repeat, in every process and in every language.
/// </para>
/// <para>A report that fails never stops a request:</para>
/// <list type="bullet">
/// <item>A network error, a <c>401</c>, <c>408</c>, <c>409</c>, <c>429</c> or a <c>5xx</c> keeps the
/// batch. The reporter sends it again after one interval. It does not read <c>Retry-After</c>.</item>
/// <item>Any other answer drops the batch, with a log line. A retry gets the same answer.</item>
/// <item>When the buffer is full, the oldest event goes, and a log line counts it.</item>
/// </list>
/// <para>
/// Nothing is written to disk. <see cref="CloseAsync"/> sends what is left at shutdown. Events it
/// cannot send in time are lost, with a log line.
/// </para>
/// </remarks>
public sealed class UsageReporter : IAsyncDisposable
{
    /// <summary>The one place that names keelie's usage endpoint.</summary>
    public const string Path = "/usage-events:report";

    /// <summary>
    /// The namespace of an outcome's key: <c>uuid5(KeelieOutcomeNamespace, outcomeId)</c>. Fixed for
    /// good, and the same in every language. A UUIDv5 and not a random key: the key must be the same
    /// on every repeat of the outcome, so that keelie charges it once.
    /// </summary>
    public static readonly Guid KeelieOutcomeNamespace = new("a29fa190-9b27-5a07-a1ba-3a0902a3bdcc");

    /// <summary>Events in one batch.</summary>
    public const int DefaultBatchSize = 50;

    /// <summary>The most events keelie takes in one batch.</summary>
    public const int MaxBatchSize = 1000;

    /// <summary>The most events the buffer holds.</summary>
    public const int DefaultMaxBufferedEvents = 10_000;

    /// <summary>
    /// At most 5 seconds. A Consumer's balance may go below zero for 60 seconds at most, and that
    /// window must hold one flush, one failed flush, a retry and a burst.
    /// </summary>
    public static readonly TimeSpan DefaultFlushInterval = TimeSpan.FromSeconds(5);

    /// <summary>How long <see cref="CloseAsync"/> tries to send what is left.</summary>
    public static readonly TimeSpan DefaultCloseTimeout = TimeSpan.FromSeconds(10);

    private const int MaxNameLength = 255;
    private const decimal MaxAmount = 1_000_000_000m;
    private const string Category = "Keelie.UsageReporter";

    private static readonly Regex ProblemCode = new("^[a-z0-9-]{1,64}$", RegexOptions.CultureInvariant);

    private readonly HttpClient _keelie;
    private readonly int _batchSize;
    private readonly TimeSpan _interval;
    private readonly int _max;
    private readonly object _gate = new();
    private readonly LinkedList<string> _events = new();
    private readonly SemaphoreSlim _wake = new(0, 1);
    private readonly CancellationTokenSource _stop = new();
    // The batch on its way, kept as sent: a retry repeats its key and its body. Only the one
    // flushing task reads or writes it.
    private Batch? _pending;
    private int _dropped;
    private bool _closed;
    private Task? _task;

    /// <summary>A reporter that sends through <paramref name="keelie"/>.</summary>
    /// <param name="keelie">
    /// keelie's address as its <see cref="HttpClient.BaseAddress"/>, and the auth of a credential
    /// that may report usage: use <see cref="SdkCredential.CreateClient"/>. It is not disposed here.
    /// </param>
    /// <param name="options">The batch size, the interval and the size of the buffer.</param>
    /// <exception cref="ArgumentOutOfRangeException">An option is out of range.</exception>
    public UsageReporter(HttpClient keelie, UsageReporterOptions? options = null)
    {
        KeelieHttp.RequireBaseAddress(keelie, nameof(keelie));
        options ??= new UsageReporterOptions();
        if (options.BatchSize is < 1 or > MaxBatchSize)
        {
            throw new ArgumentOutOfRangeException(nameof(options), $"BatchSize must be from 1 to {MaxBatchSize}");
        }
        if (options.FlushInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "FlushInterval must be more than 0");
        }
        if (options.MaxBufferedEvents < options.BatchSize)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxBufferedEvents must be at least BatchSize");
        }
        _keelie = keelie;
        _batchSize = options.BatchSize;
        _interval = options.FlushInterval;
        _max = options.MaxBufferedEvents;
    }

    /// <summary>Put one event in the buffer, and return at once.</summary>
    /// <remarks>
    /// It never throws and never waits on the network. An event keelie would refuse is logged and
    /// left out, so it cannot cost the other events of its batch.
    /// </remarks>
    /// <param name="clientId"><c>claims.Azp</c>: the Consumer's credential, or the agent's client on a token for a person.</param>
    /// <param name="capabilityKey">The route or the tool that was called, such as <c>GET /v1/orders/{orderId}</c>. 255 characters at most.</param>
    /// <param name="unit">What the event counts.</param>
    /// <param name="quantity">How many units: more than 0, at most six decimal places.</param>
    /// <param name="credits">What the call costs the Consumer's balance. Leave it out when the call is free.</param>
    /// <param name="outcomeId">
    /// The ID of the outcome of a <see cref="UsageUnit.Outcome"/> event, such as the ID of the job.
    /// It must be unique across all your Consumers. keelie charges the outcome once, however often it
    /// is reported. An outcome with credits needs it. Any other unit must not have it.
    /// </param>
    /// <param name="consumerId">
    /// <c>claims.ConsumerId</c>: the Consumer of a token for a person, whose credits the call burns.
    /// Always pass it. It is <see langword="null"/> on a credential's token, and nothing is sent.
    /// </param>
    public void Record(
        string clientId,
        string capabilityKey,
        UsageUnit unit = UsageUnit.Request,
        decimal quantity = 1,
        decimal? credits = null,
        string? outcomeId = null,
        Guid? consumerId = null)
    {
        lock (_gate)
        {
            if (_closed)
            {
                return;
            }
        }
        var amount = FormatAmount(quantity, positive: true);
        var cost = credits is { } c ? FormatAmount(c, positive: false) : null;
        var unitName = UnitName(unit);
        string? reason = null;
        if (!NameOk(clientId))
        {
            reason = "client_id";
        }
        else if (!NameOk(capabilityKey))
        {
            reason = "capability_key";
        }
        else if (unitName is null)
        {
            reason = "unit";
        }
        else if (amount is null)
        {
            reason = "quantity";
        }
        else if (credits is not null && cost is null)
        {
            reason = "credits";
        }
        else if (outcomeId is not null && (unit != UsageUnit.Outcome || !NameOk(outcomeId)))
        {
            reason = "outcome_id";
        }
        else if (outcomeId is null && unit == UsageUnit.Outcome && credits > 0)
        {
            // Without the ID, each repeat of the outcome would burn the balance again.
            reason = "outcome_id";
        }
        if (reason is not null)
        {
            // A fixed word: the value can come from the request, and stays out of the log.
            Log.Warn(Category, "apiable.usage_event_invalid reason={Reason}", reason);
            return;
        }

        var key = outcomeId is null ? Guid.NewGuid() : Uuid5.Create(KeelieOutcomeNamespace, outcomeId);
        var json = new StringBuilder("{\"idempotency_key\":");
        Compat.WriteJsonString(json, key.ToString("D"));
        json.Append(",\"client_id\":");
        Compat.WriteJsonString(json, clientId);
        json.Append(",\"capability_key\":");
        Compat.WriteJsonString(json, capabilityKey);
        json.Append(",\"unit\":");
        Compat.WriteJsonString(json, unitName!);
        json.Append(",\"quantity\":");
        Compat.WriteJsonString(json, amount!);
        json.Append(",\"ts\":");
        Compat.WriteJsonString(json, DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'", CultureInfo.InvariantCulture));
        if (cost is not null)
        {
            json.Append(",\"credits\":");
            Compat.WriteJsonString(json, cost);
        }
        if (consumerId is { } consumer)
        {
            json.Append(",\"consumer_id\":");
            Compat.WriteJsonString(json, consumer.ToString("D"));
        }
        json.Append('}');

        bool full;
        lock (_gate)
        {
            if (_closed)
            {
                return;
            }
            if (_events.Count >= _max)
            {
                // The oldest event goes to take this one.
                _events.RemoveFirst();
                _dropped++;
            }
            _events.AddLast(json.ToString());
            full = _events.Count >= _batchSize;
            _task ??= Task.Run(RunAsync);
        }
        if (full)
        {
            Wake();
        }
    }

    /// <summary>Start the background task. <see cref="Record"/> starts it too; this is for a process that wants it running first.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (!_closed)
            {
                _task ??= Task.Run(RunAsync);
            }
        }
    }

    /// <summary>
    /// Stop the background task, and send what is in the buffer, once.
    /// </summary>
    /// <remarks>
    /// If a batch fails, or <paramref name="timeout"/> passes, what is not sent is dropped, with one
    /// log line. It never throws.
    /// </remarks>
    /// <param name="timeout">How long to try. 10 seconds unless you give another.</param>
    public async Task CloseAsync(TimeSpan? timeout = null)
    {
        Task? task;
        lock (_gate)
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
            task = _task;
        }
        await _stop.CancelAsync().ConfigureAwait(false);
        if (task is not null)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        using var expired = new CancellationTokenSource(timeout ?? DefaultCloseTimeout);
        try
        {
            await FlushAsync(expired.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Timed out, or failed: what is left is counted below.
        }
        int lost;
        lock (_gate)
        {
            lost = _events.Count;
        }
        lost += _pending?.Count ?? 0;
        if (lost > 0)
        {
            Log.Warn(Category, "apiable.usage_dropped events={Events} reason=closed", lost);
        }
    }

    /// <summary>The same as <see cref="CloseAsync"/>, with its default timeout.</summary>
    public async ValueTask DisposeAsync() => await CloseAsync().ConfigureAwait(false);

    private void Wake()
    {
        try
        {
            if (_wake.CurrentCount == 0)
            {
                _wake.Release();
            }
        }
        catch (SemaphoreFullException)
        {
            // Already awake.
        }
    }

    private async Task RunAsync()
    {
        var stop = _stop.Token;
        var retry = false;
        while (!stop.IsCancellationRequested)
        {
            if (!retry)
            {
                try
                {
                    await _wake.WaitAsync(_interval, stop).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
            // Clear the wake: a batch that fills while this flush runs wakes the next.
            _wake.Wait(0, CancellationToken.None);
            try
            {
                retry = !await FlushAsync(stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                // The task must outlive any failure.
                Log.Warn(Category, "apiable.usage_flush_failed error={Error}", Log.ErrorName(error));
                retry = true;
            }
            if (retry)
            {
                // keelie or the network failed. Wait one interval, whatever fills the buffer, then
                // send the same batch again.
                try
                {
                    await Task.Delay(_interval, stop).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    /// <summary>Send every batch in the buffer. False if a batch must be sent again later.</summary>
    private async Task<bool> FlushAsync(CancellationToken cancel)
    {
        try
        {
            while (true)
            {
                if (_pending is null)
                {
                    _pending = NextBatch();
                    if (_pending is null)
                    {
                        return true;
                    }
                }
                if (!await SendAsync(_pending, cancel).ConfigureAwait(false))
                {
                    return false;
                }
                _pending = null;
            }
        }
        finally
        {
            LogDropped();
        }
    }

    private Batch? NextBatch()
    {
        var body = new StringBuilder("{\"events\":[");
        var count = 0;
        lock (_gate)
        {
            while (_events.First is { } first && count < _batchSize)
            {
                if (count > 0)
                {
                    body.Append(',');
                }
                body.Append(first.Value);
                _events.RemoveFirst();
                count++;
            }
        }
        if (count == 0)
        {
            return null;
        }
        body.Append("]}");
        return new Batch(Guid.NewGuid().ToString("D"), Encoding.UTF8.GetBytes(body.ToString()), count);
    }

    /// <summary>Send one batch. True when it is done with: kept by keelie, or dropped.</summary>
    private async Task<bool> SendAsync(Batch batch, CancellationToken cancel)
    {
        HttpResponseMessage response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, KeelieHttp.UriFor(_keelie, Path));
            request.Content = new ByteArrayContent(batch.Body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Headers.Add("Idempotency-Key", batch.Key);
            response = await _keelie.SendAsync(request, cancel).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            Log.Warn(Category, "apiable.usage_not_sent events={Events} error={Error}", batch.Count, Log.ErrorName(error));
            return false;
        }
        using (response)
        {
            var status = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                Log.Debug(Category, "apiable.usage_sent events={Events}", batch.Count);
                return true;
            }
            if (status is 401 or 408 or 409 or 429 || status >= 500)
            {
                Log.Warn(Category, "apiable.usage_not_sent events={Events} status={Status}", batch.Count, status);
                return false;
            }
            Log.Warn(
                Category,
                "apiable.usage_dropped events={Events} status={Status} type={Type}",
                batch.Count,
                status,
                await ProblemTypeAsync(response, cancel).ConfigureAwait(false));
            return true;
        }
    }

    private void LogDropped()
    {
        int dropped;
        lock (_gate)
        {
            dropped = _dropped;
            _dropped = 0;
        }
        if (dropped > 0)
        {
            Log.Warn(Category, "apiable.usage_dropped events={Events} reason=buffer_full", dropped);
        }
    }

    private static string? UnitName(UsageUnit unit) => unit switch
    {
        UsageUnit.Request => "request",
        UsageUnit.ToolCall => "tool_call",
        UsageUnit.Token => "token",
        UsageUnit.Outcome => "outcome",
        _ => null,
    };

    private static bool NameOk(string? name)
    {
        if (name is null || name.Length == 0 || Compat.CodePoints(name) > MaxNameLength)
        {
            return false;
        }
        foreach (var c in name)
        {
            if (c < ' ' || c == '\u007f')
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// The amount as keelie reads it, a plain decimal with no sign and at most six places, or
    /// <see langword="null"/> if keelie would refuse it. Zeros past the sixth place are dropped.
    /// </summary>
    internal static string? FormatAmount(decimal value, bool positive)
    {
        if (decimal.IsNegative(value) || value > MaxAmount || (positive && value == 0))
        {
            return null;
        }
        var places = value.Scale;
        if (places > 6)
        {
            var rounded = Math.Round(value, 6, MidpointRounding.ToZero);
            if (rounded != value)
            {
                return null;
            }
            value = rounded;
        }
        return value.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>The last segment of the problem's <c>type</c>, such as <c>usage-out-of-range</c>.</summary>
    private static async Task<string> ProblemTypeAsync(HttpResponseMessage response, CancellationToken cancel)
    {
        try
        {
            var body = await response.Content.ReadAsByteArrayAsync(cancel).ConfigureAwait(false);
            using var problem = JsonDocument.Parse(body);
            if (problem.RootElement.ValueKind != JsonValueKind.Object
                || !problem.RootElement.TryGetProperty("type", out var type)
                || type.ValueKind != JsonValueKind.String)
            {
                return "unknown";
            }
            var kind = type.GetString()!.TrimEnd('/');
            var code = kind[(kind.LastIndexOf('/') + 1)..];
            // keelie's codes are short and plain. Anything else stays out of the log.
            return ProblemCode.IsMatch(code) ? code : "unknown";
        }
        catch (Exception error) when (error is JsonException or HttpRequestException or IOException or OperationCanceledException)
        {
            return "unknown";
        }
    }

    private sealed record Batch(string Key, byte[] Body, int Count);
}
