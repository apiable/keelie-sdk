<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Internal\Json;
use Keelie\Internal\JsonObject;
use Keelie\Internal\Uuid;

/**
 * Report usage to keelie in batches, off the request path.
 *
 * {@see record()} puts one event in a buffer in memory and returns. It does no I/O,
 * so it adds no time to the request that calls it. The buffer is sent to keelie's
 * usage endpoint after the response:
 *
 * - Under PHP-FPM, each request has its own memory. When the request ends, the
 *   reporter first ends the response to the client, with `fastcgi_finish_request()`,
 *   then sends the buffer. The client does not wait for the report.
 * - In a worker that serves many requests, such as RoadRunner, Swoole, FrankenPHP
 *   or Laravel Octane, call {@see flushIfDue()} after each response. It sends a
 *   full batch at once, and the rest after 5 seconds. {@see close()} sends what is
 *   left when the worker stops.
 *
 * What the SDK reports is telemetry. It feeds the Provider's dashboards and the
 * Consumer's spend cap. Apiable never puts it on an invoice.
 *
 * Each event carries its own idempotency key, and each batch carries an
 * `Idempotency-Key`. A batch that fails on the way is sent again later with the
 * same key and the same body, so keelie keeps each event once.
 *
 * A token for a person names its Consumer in `consumer_id`: its `azp` is an
 * agent's client, which serves every Consumer. Pass `$claims->consumerId` to
 * {@see record()} with each event. keelie then burns that Consumer's credits. On a
 * credential's token it is null, and nothing is sent.
 *
 * An outcome is charged once. `record(..., unit: 'outcome', outcomeId: ...)` makes
 * the event's key from the outcome ID, with {@see KEELIE_OUTCOME_NAMESPACE}. The
 * same outcome then has the same key on every repeat, in every process and in
 * every language, and keelie keeps the key in every month. A repeat burns nothing.
 *
 * A report that fails never stops a request:
 *
 * - A network error, a 401, 408, 409, 429 or a 5xx keeps the batch. It is sent
 *   again after one interval. Under PHP-FPM there is no later: the batch is
 *   dropped when the request ends, with a log line.
 * - Any other answer drops the batch, with a log line. A retry gets the same
 *   answer. `usage-out-of-range` is one of these.
 * - When the buffer is full, the oldest event goes, and a log line counts it.
 *
 * Nothing is written to disk.
 */
final class UsageReporter
{
    /** The one place that names keelie's usage endpoint. */
    public const PATH = '/usage-events:report';
    public const UNITS = ['request', 'tool_call', 'token', 'outcome'];
    /**
     * The namespace of an outcome's key: uuid5(KEELIE_OUTCOME_NAMESPACE, outcomeId).
     * Fixed for good, and the same in every language.
     */
    public const KEELIE_OUTCOME_NAMESPACE = 'a29fa190-9b27-5a07-a1ba-3a0902a3bdcc';
    // What keelie takes in one event, and in one batch.
    public const MAX_NAME_LENGTH = 255;
    public const MAX_BATCH_SIZE = 1000;
    public const BATCH_SIZE = 50;
    /**
     * At most 5 seconds. A Consumer's balance may go below zero for 60 seconds at
     * most, and that window must hold one flush, one failed flush, a retry and a burst.
     */
    public const FLUSH_INTERVAL_SECONDS = 5.0;
    public const MAX_BUFFERED_EVENTS = 10000;
    public const CLOSE_TIMEOUT_SECONDS = 10.0;
    /** The answers that can change on a retry. A 401 is one: the credential mints a new token. */
    private const RETRY_STATUSES = [401, 408, 409, 429];
    private const MAX_AMOUNT_DIGITS = 10; // 10 ** 9, the largest amount, has ten digits
    private const PLACES = 6;

    private readonly \Closure $clock;
    /** @var list<array<string, string>> */
    private array $events = [];
    /** When the oldest event in the buffer was recorded. */
    private ?float $oldestAt = null;
    /** @var array{key: string, body: string, count: int}|null the batch on its way, kept as sent */
    private ?array $pending = null;
    private ?float $failedAt = null;
    private int $dropped = 0;
    private bool $closed = false;

    /**
     * Make one reporter for the process.
     *
     * @param KeelieClient $keelie sends a request to keelie with the auth of a
     *                             credential that may report usage: an SdkCredential
     * @param bool $sendAtShutdown send what is left when PHP shuts down, after the response
     * @param (\Closure(): float)|null $clock seconds since the epoch
     *
     * @throws \InvalidArgumentException when an option is out of range
     */
    public function __construct(
        private readonly KeelieClient $keelie,
        private readonly int $batchSize = self::BATCH_SIZE,
        private readonly float $flushIntervalSeconds = self::FLUSH_INTERVAL_SECONDS,
        private readonly int $maxBufferedEvents = self::MAX_BUFFERED_EVENTS,
        bool $sendAtShutdown = true,
        ?\Closure $clock = null,
    ) {
        if ($batchSize < 1 || $batchSize > self::MAX_BATCH_SIZE) {
            throw new \InvalidArgumentException('batchSize must be from 1 to ' . self::MAX_BATCH_SIZE);
        }
        if (!($flushIntervalSeconds > 0)) {
            throw new \InvalidArgumentException('flushIntervalSeconds must be more than 0');
        }
        if ($maxBufferedEvents < $batchSize) {
            throw new \InvalidArgumentException('maxBufferedEvents must be at least batchSize');
        }
        $this->clock = $clock ?? static fn (): float => microtime(true);
        if ($sendAtShutdown) {
            register_shutdown_function(function (): void {
                $this->shutdown();
            });
        }
    }

    /**
     * Put one event in the buffer, and return at once.
     *
     * An event keelie would refuse is logged and left out, so it cannot cost the
     * other events of its batch.
     *
     * @param string $clientId the `azp` of the Consumer's token
     * @param string $capabilityKey the route or the tool that was called
     * @param string $unit "request", "tool_call", "token" or "outcome"
     * @param int|float|string $quantity how many units: a whole number, or a decimal with at most six places
     * @param int|float|string|null $credits what the call costs the Consumer's balance. Leave it out when the call is free.
     *                                       A string, such as "0.25", keeps exact cents that a float cannot.
     * @param string|null $outcomeId the outcome of a "outcome" event, such as the ID of the job. It must be
     *                               unique across all your Consumers. An outcome with credits needs it.
     *                               Any other unit must not have it.
     * @param string|null $consumerId `$claims->consumerId`. Always pass it.
     */
    public function record(
        string $clientId,
        string $capabilityKey,
        string $unit = 'request',
        int|float|string $quantity = 1,
        int|float|string|null $credits = null,
        ?string $outcomeId = null,
        ?string $consumerId = null,
    ): void {
        if ($this->closed) {
            return;
        }
        try {
            $event = $this->event($clientId, $capabilityKey, $unit, $quantity, $credits, $outcomeId, $consumerId);
        } catch (\Throwable) {
            // Nothing a caller passes may throw from here. The event is left out, as an invalid one is.
            Log::warning('apiable.usage_event_invalid reason=options');

            return;
        }
        if ($event === null) {
            return;
        }
        if (count($this->events) >= $this->maxBufferedEvents) {
            // The oldest event goes to take this one.
            array_shift($this->events);
            $this->dropped++;
        }
        $this->events[] = $event;
        $this->oldestAt ??= $this->now();
    }

    /**
     * Send what is due: a full batch, events older than one interval, or a batch
     * that failed one interval ago. Call it after each response in a worker that
     * serves many requests. It never throws.
     */
    public function flushIfDue(): void
    {
        $due = $this->pending !== null
            || count($this->events) >= $this->batchSize
            || ($this->oldestAt !== null && $this->now() - $this->oldestAt >= $this->flushIntervalSeconds);
        if ($due) {
            $this->flush();
        }
    }

    /**
     * Send every event in the buffer now. It never throws.
     *
     * A batch that fails is kept and sent again, with the same key, by the next
     * flush one interval later or more.
     */
    public function flush(): void
    {
        if ($this->failedAt !== null && $this->now() - $this->failedAt < $this->flushIntervalSeconds) {
            return;
        }
        $this->sendAll(null);
    }

    /**
     * Send what is in the buffer, once, and take no more events.
     *
     * If a batch fails, or `$timeoutSeconds` pass, what is not sent is dropped,
     * with one log line. A batch that is on its way when the time runs out
     * finishes first. It never throws.
     */
    public function close(float $timeoutSeconds = self::CLOSE_TIMEOUT_SECONDS): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        $this->sendAll($this->now() + $timeoutSeconds);
        $lost = count($this->events) + ($this->pending['count'] ?? 0);
        if ($lost > 0) {
            Log::warning("apiable.usage_dropped events={$lost} reason=closed");
        }
        $this->events = [];
        $this->pending = null;
    }

    /** The events in the buffer, and in a batch on its way. */
    public function buffered(): int
    {
        return count($this->events) + ($this->pending['count'] ?? 0);
    }

    /** @internal Called when PHP shuts down. */
    public function shutdown(): void
    {
        if ($this->closed) {
            return;
        }
        if ($this->buffered() > 0) {
            // End the response first: the client must not wait for the report.
            if (PHP_SAPI === 'fpm-fcgi' && function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            } elseif (function_exists('litespeed_finish_request')) {
                litespeed_finish_request();
            }
        }
        $this->close();
    }

    private function now(): float
    {
        return (float) ($this->clock)();
    }

    /** Send every batch, until one fails or the deadline passes. */
    private function sendAll(?float $deadline): void
    {
        try {
            while ($this->pending !== null || $this->events !== []) {
                if ($deadline !== null && $this->now() >= $deadline) {
                    return;
                }
                $this->pending ??= $this->nextBatch();
                if (!$this->send($this->pending)) {
                    $this->failedAt = $this->now();

                    return;
                }
                $this->pending = null;
                $this->failedAt = null;
            }
        } catch (\Throwable $error) {
            // The reporter must outlive any failure.
            Log::warning('apiable.usage_flush_failed error=' . Log::errorName($error));
            $this->failedAt = $this->now();
        } finally {
            if ($this->dropped > 0) {
                Log::warning("apiable.usage_dropped events={$this->dropped} reason=buffer_full");
                $this->dropped = 0;
            }
        }
    }

    /** @return array{key: string, body: string, count: int} */
    private function nextBatch(): array
    {
        $events = array_splice($this->events, 0, $this->batchSize);
        $this->oldestAt = $this->events === [] ? null : $this->now();

        return [
            'key' => Uuid::v4(),
            'body' => json_encode(['events' => $events], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'count' => count($events),
        ];
    }

    /**
     * Send one batch. True when it is done with: kept by keelie, or dropped.
     *
     * @param array{key: string, body: string, count: int} $batch
     */
    private function send(array $batch): bool
    {
        $count = $batch['count'];
        try {
            $response = $this->keelie->request('POST', self::PATH, $batch['body'], [
                'Content-Type' => 'application/json',
                'Idempotency-Key' => $batch['key'],
            ]);
        } catch (\Throwable $error) {
            Log::warning("apiable.usage_not_sent events={$count} error=" . Log::errorName($error));

            return false;
        }
        $status = $response->status;
        if ($response->ok()) {
            Log::debug("apiable.usage_sent events={$count}");

            return true;
        }
        if (in_array($status, self::RETRY_STATUSES, true) || $status >= 500) {
            Log::warning("apiable.usage_not_sent events={$count} status={$status}");

            return false;
        }
        Log::warning("apiable.usage_dropped events={$count} status={$status} type=" . self::problemType($response->body));

        return true;
    }

    /**
     * The event to send, or null, with a log line, when keelie would refuse it.
     *
     * @return array<string, string>|null
     */
    private function event(
        string $clientId,
        string $capabilityKey,
        string $unit,
        int|float|string $quantity,
        int|float|string|null $credits,
        ?string $outcomeId,
        ?string $consumerId,
    ): ?array {
        $amount = self::formatAmount($quantity, true);
        $cost = $credits === null ? null : self::formatAmount($credits, false);
        $consumer = $consumerId === null ? null : Uuid::parse($consumerId);
        $reason = match (true) {
            !self::nameOk($clientId) => 'client_id',
            !self::nameOk($capabilityKey) => 'capability_key',
            !in_array($unit, self::UNITS, true) => 'unit',
            $amount === null => 'quantity',
            $credits !== null && $cost === null => 'credits',
            $outcomeId !== null && ($unit !== 'outcome' || !self::nameOk($outcomeId)) => 'outcome_id',
            // Without the ID, each repeat of the outcome would burn the balance again.
            $outcomeId === null && $unit === 'outcome' && $cost !== null && preg_match('/[1-9]/', $cost) === 1
                => 'outcome_id',
            $consumerId !== null && $consumer === null => 'consumer_id',
            default => null,
        };
        if ($reason !== null) {
            // A fixed word: the value can come from the request, and stays out of the log.
            Log::warning("apiable.usage_event_invalid reason={$reason}");

            return null;
        }
        $at = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $this->now()), new \DateTimeZone('UTC'));
        $event = [
            'idempotency_key' => $outcomeId === null ? Uuid::v4() : Uuid::v5(self::KEELIE_OUTCOME_NAMESPACE, $outcomeId),
            'client_id' => $clientId,
            'capability_key' => $capabilityKey,
            'unit' => $unit,
            'quantity' => (string) $amount,
            'ts' => $at === false ? gmdate('Y-m-d\TH:i:s\Z') : $at->format('Y-m-d\TH:i:s.v\Z'),
        ];
        if ($cost !== null) {
            $event['credits'] = $cost;
        }
        if ($consumer !== null) {
            $event['consumer_id'] = $consumer;
        }

        return $event;
    }

    private static function nameOk(string $name): bool
    {
        if ($name === '' || preg_match('//u', $name) !== 1 || preg_match('/[\x00-\x1f\x7f]/', $name) === 1) {
            return false;
        }

        return preg_match_all('/./us', $name) <= self::MAX_NAME_LENGTH;
    }

    /**
     * The amount as keelie reads it, a plain decimal string with no sign and at
     * most six places, or null if keelie would refuse it.
     *
     * @internal
     */
    public static function formatAmount(mixed $value, bool $positive): ?string
    {
        if (is_int($value)) {
            $text = (string) $value;
        } elseif (is_float($value)) {
            if (!is_finite($value)) {
                return null;
            }
            // The shortest decimal that reads back as this number. An exponent means
            // more places, or more digits, than keelie keeps.
            $text = json_encode($value, JSON_THROW_ON_ERROR);
        } elseif (is_string($value)) {
            $text = $value;
        } else {
            return null;
        }
        if (preg_match('/^(\d+)(?:\.(\d+))?$/D', $text, $match) !== 1) {
            return null;
        }
        $whole = ltrim($match[1], '0');
        $whole = $whole === '' ? '0' : $whole;
        $fraction = $match[2] ?? '';
        // Zeros past the sixth place change nothing, and keelie reads six at most.
        if (strlen($fraction) > self::PLACES) {
            if (preg_match('/[1-9]/', substr($fraction, self::PLACES)) === 1) {
                return null;
            }
            $fraction = substr($fraction, 0, self::PLACES);
        }
        if (strlen($whole) > self::MAX_AMOUNT_DIGITS) {
            return null;
        }
        if (strlen($whole) === self::MAX_AMOUNT_DIGITS && ($whole !== '1000000000' || preg_match('/[1-9]/', $fraction) === 1)) {
            return null;
        }
        if ($positive && preg_match('/[1-9]/', $whole . $fraction) !== 1) {
            return null;
        }

        return $fraction === '' ? $whole : "{$whole}.{$fraction}";
    }

    /** The last segment of the problem's `type`, such as `usage-out-of-range`. */
    private static function problemType(string $body): string
    {
        try {
            $problem = Json::lenient($body);
        } catch (\Throwable) {
            return 'unknown';
        }
        $type = $problem instanceof JsonObject ? $problem->get('type') : null;
        if (!is_string($type)) {
            return 'unknown';
        }
        $segments = explode('/', rtrim($type, '/'));
        $code = (string) end($segments);

        // keelie's codes are short and plain. Anything else stays out of the log.
        return preg_match('/^[a-z0-9-]{1,64}$/D', $code) === 1 ? $code : 'unknown';
    }
}
