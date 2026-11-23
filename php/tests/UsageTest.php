<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\Http\Response;
use Keelie\Http\TransportError;
use Keelie\Log;
use Keelie\UsageReporter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UsageTest extends TestCase
{
    private Logs $logs;
    private Clock $clock;

    protected function setUp(): void
    {
        $this->logs = Support::logs();
        $this->clock = new Clock();
    }

    protected function tearDown(): void
    {
        Log::setLogger(null);
    }

    private function reporter(FakeKeelie $keelie, int $batchSize = 50, int $max = 10000): UsageReporter
    {
        return new UsageReporter($keelie, $batchSize, 5.0, $max, sendAtShutdown: false, clock: $this->clock->closure());
    }

    public function testRecordDoesNoIoAndFlushSendsOneBatch(): void
    {
        $keelie = new FakeKeelie();
        $reporter = $this->reporter($keelie);
        $reporter->record('client', 'GET /v1/orders/{id}', credits: '0.25', consumerId: strtoupper(Support::CONSUMER_ID));
        $reporter->record('client', 'GET /v1/orders/{id}');
        self::assertSame([], $keelie->requests);

        $reporter->flush();

        self::assertCount(1, $keelie->requests);
        $request = $keelie->requests[0];
        self::assertSame(['POST', UsageReporter::PATH], [$request['method'], $request['path']]);
        self::assertSame('application/json', $request['headers']['Content-Type']);
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $request['headers']['Idempotency-Key']);
        $events = $keelie->events(0);
        self::assertSame('client', $events[0]['client_id']);
        self::assertSame('request', $events[0]['unit']);
        self::assertSame('1', $events[0]['quantity']);
        self::assertSame('0.25', $events[0]['credits']);
        self::assertSame(Support::CONSUMER_ID, $events[0]['consumer_id']);
        self::assertSame('2027-01-15T08:00:00.000Z', $events[0]['ts']);
        self::assertArrayNotHasKey('credits', $events[1]);
        self::assertNotSame($events[0]['idempotency_key'], $events[1]['idempotency_key']);
        self::assertSame(0, $reporter->buffered());
    }

    public function testAnOutcomeHasTheSameKeyInEveryLanguage(): void
    {
        $keelie = new FakeKeelie();
        $reporter = $this->reporter($keelie);
        $reporter->record('client', 'POST /videos', unit: 'outcome', credits: 50, outcomeId: 'job-42');
        $reporter->record('client', 'POST /videos', unit: 'outcome', credits: 50, outcomeId: 'job-42');
        $reporter->flush();

        // uuid.uuid5(KEELIE_OUTCOME_NAMESPACE, "job-42") in Python.
        foreach ($keelie->events(0) as $event) {
            self::assertSame('e13e60df-e85b-588a-a945-f15fed07d021', $event['idempotency_key']);
        }
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalidEvents(): iterable
    {
        yield 'an empty client' => [['clientId' => ''], 'client_id'];
        yield 'a client too long' => [['clientId' => str_repeat('é', 256)], 'client_id'];
        yield 'a control character' => [['capabilityKey' => "GET /a\n"], 'capability_key'];
        yield 'a capability that is not UTF-8' => [['capabilityKey' => "\xff"], 'capability_key'];
        yield 'an unknown unit' => [['unit' => 'minute'], 'unit'];
        yield 'a zero quantity' => [['quantity' => 0], 'quantity'];
        yield 'a negative quantity' => [['quantity' => -1], 'quantity'];
        yield 'seven places' => [['quantity' => '0.0000001'], 'quantity'];
        yield 'too large' => [['credits' => 1000000001], 'credits'];
        yield 'an exponent' => [['credits' => 1e-7], 'credits'];
        yield 'not a number' => [['credits' => 'one'], 'credits'];
        yield 'an outcome on a request' => [['outcomeId' => 'job-1'], 'outcome_id'];
        yield 'an outcome with credits and no ID' => [['unit' => 'outcome', 'credits' => 5], 'outcome_id'];
        yield 'a consumer that is not a UUID' => [['consumerId' => 'nobody'], 'consumer_id'];
    }

    /** @param array<string, mixed> $arguments */
    #[DataProvider('invalidEvents')]
    public function testAnEventKeelieWouldRefuseIsLeftOutWithALogLine(array $arguments, string $reason): void
    {
        $keelie = new FakeKeelie();
        $reporter = $this->reporter($keelie);
        $reporter->record(...array_merge(['clientId' => 'client', 'capabilityKey' => 'GET /a'], $arguments));

        self::assertSame(0, $reporter->buffered());
        self::assertStringContainsString("apiable.usage_event_invalid reason={$reason}", $this->logs->text());
    }

    /** @return iterable<string, array{int|float|string, string}> */
    public static function amounts(): iterable
    {
        yield 'an int' => [3, '3'];
        yield 'a float' => [0.25, '0.25'];
        yield 'a whole float' => [2.0, '2'];
        yield 'a string' => ['1.50', '1.50'];
        yield 'zeros past six places' => ['0.0000010', '0.000001'];
        yield 'leading zeros' => ['007', '7'];
        yield 'the largest' => ['1000000000', '1000000000'];
    }

    #[DataProvider('amounts')]
    public function testAnAmountIsSentAsKeelieReadsIt(int|float|string $amount, string $sent): void
    {
        self::assertSame($sent, UsageReporter::formatAmount($amount, true));
    }

    public function testAFullBatchIsDueAtOnceAndTheRestAfterOneInterval(): void
    {
        $keelie = new FakeKeelie();
        $reporter = $this->reporter($keelie, batchSize: 2);
        $reporter->record('client', 'GET /a');
        $reporter->flushIfDue();
        self::assertCount(0, $keelie->requests);

        $reporter->record('client', 'GET /a');
        $reporter->flushIfDue();
        self::assertCount(1, $keelie->requests);

        $reporter->record('client', 'GET /a');
        $reporter->flushIfDue();
        self::assertCount(1, $keelie->requests);
        $this->clock->now += 5;
        $reporter->flushIfDue();
        self::assertCount(2, $keelie->requests);
    }

    /** @return iterable<string, array{Response|\Throwable}> */
    public static function retried(): iterable
    {
        yield 'a network error' => [new TransportError('down')];
        yield '401' => [new Response(401)];
        yield '408' => [new Response(408)];
        yield '409' => [new Response(409)];
        yield '429' => [new Response(429)];
        yield '503' => [new Response(503)];
    }

    #[DataProvider('retried')]
    public function testAFailedBatchIsSentAgainWithTheSameKeyAfterOneInterval(Response|\Throwable $failure): void
    {
        $keelie = new FakeKeelie([$failure]);
        $reporter = $this->reporter($keelie);
        $reporter->record('client', 'GET /a');
        $reporter->flush();
        self::assertSame(1, $reporter->buffered());

        $reporter->flush(); // too soon: no request
        self::assertCount(1, $keelie->requests);
        $this->clock->now += 5;
        $reporter->flushIfDue();

        self::assertCount(2, $keelie->requests);
        self::assertSame($keelie->requests[0]['headers']['Idempotency-Key'], $keelie->requests[1]['headers']['Idempotency-Key']);
        self::assertSame($keelie->requests[0]['body'], $keelie->requests[1]['body']);
        self::assertSame(0, $reporter->buffered());
        self::assertStringContainsString('apiable.usage_not_sent events=1', $this->logs->text());
    }

    public function testAnyOtherAnswerDropsTheBatchWithTheProblemType(): void
    {
        $keelie = new FakeKeelie([new Response(422, [], '{"type":"https://keelie.io/problems/usage-out-of-range"}')]);
        $reporter = $this->reporter($keelie);
        $reporter->record('client', 'GET /a');
        $reporter->flush();

        self::assertSame(0, $reporter->buffered());
        self::assertStringContainsString('apiable.usage_dropped events=1 status=422 type=usage-out-of-range', $this->logs->text());
    }

    public function testAFullBufferDropsTheOldestEvent(): void
    {
        $keelie = new FakeKeelie();
        $reporter = $this->reporter($keelie, batchSize: 2, max: 2);
        foreach (['GET /1', 'GET /2', 'GET /3'] as $route) {
            $reporter->record('client', $route);
        }
        $reporter->flush();

        self::assertSame(['GET /2', 'GET /3'], array_column($keelie->events(0), 'capability_key'));
        self::assertStringContainsString('apiable.usage_dropped events=1 reason=buffer_full', $this->logs->text());
    }

    public function testCloseSendsWhatIsLeftOnceAndTakesNoMore(): void
    {
        $keelie = new FakeKeelie([new Response(503)]);
        $reporter = $this->reporter($keelie);
        $reporter->record('client', 'GET /a');
        $reporter->close();
        $reporter->record('client', 'GET /b');
        $reporter->close();

        self::assertCount(1, $keelie->requests);
        self::assertSame(0, $reporter->buffered());
        self::assertStringContainsString('apiable.usage_dropped events=1 reason=closed', $this->logs->text());
    }

    public function testShutdownSendsWhatIsLeft(): void
    {
        $keelie = new FakeKeelie();
        $reporter = $this->reporter($keelie);
        $reporter->record('client', 'GET /a');
        $reporter->shutdown();

        self::assertCount(1, $keelie->requests);
    }

    public function testBadOptionsAreRefusedWhenTheReporterIsMade(): void
    {
        foreach ([[0, 5.0, 10], [1001, 5.0, 2000], [10, 0.0, 10], [10, 5.0, 9]] as [$batch, $interval, $max]) {
            try {
                new UsageReporter(new FakeKeelie(), $batch, $interval, $max, false);
                self::fail("{$batch} {$interval} {$max} passed");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }
}
