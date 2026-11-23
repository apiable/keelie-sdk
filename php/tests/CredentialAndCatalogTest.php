<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\AiCatalog;
use Keelie\Http\CurlTransport;
use Keelie\Http\Response;
use Keelie\Http\Transport;
use Keelie\Http\TransportError;
use Keelie\Log;
use Keelie\ProtectedResourceMetadata;
use Keelie\SdkCredential;
use PHPUnit\Framework\TestCase;

/** The token endpoint and keelie, behind one fake transport. */
final class FakeKeelieServer implements Transport
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string, timeout: ?float}> */
    public array $requests = [];
    public int $minted = 0;
    /** @var list<Response> */
    public array $keelieAnswers = [];
    /** Run before each answer, such as to move a clock on. */
    public ?\Closure $onSend = null;

    public function send(string $method, string $url, array $headers = [], ?string $body = null, ?float $timeoutSeconds = null): Response
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body, 'timeout' => $timeoutSeconds];
        if ($this->onSend !== null) {
            ($this->onSend)();
        }
        if ($url === 'https://issuer.keelie.io/token') {
            $this->minted++;

            return new Response(200, [], (string) json_encode(['access_token' => "token-{$this->minted}", 'expires_in' => 300]));
        }

        return array_shift($this->keelieAnswers) ?? new Response(200, [], 'ok');
    }
}

final class CredentialAndCatalogTest extends TestCase
{
    private Logs $logs;

    protected function setUp(): void
    {
        $this->logs = Support::logs();
    }

    protected function tearDown(): void
    {
        Log::setLogger(null);
    }

    private static function credential(FakeKeelieServer $server, Clock $clock, ?ArrayCache $cache = null): SdkCredential
    {
        return new SdkCredential(
            'https://keelie.example.com/',
            'https://issuer.keelie.io/token',
            'sdk-client',
            's3cret value',
            http: $server,
            cache: $cache,
            clock: $clock->closure(),
        );
    }

    public function testTheCredentialMintsOnceAndSendsTheTokenToKeelie(): void
    {
        $server = new FakeKeelieServer();
        $clock = new Clock();
        $credential = self::credential($server, $clock);
        $credential->request('POST', '/usage-events:report', '{}', ['Content-Type' => 'application/json']);
        $credential->request('GET', '/ai-catalog');

        self::assertSame(1, $server->minted);
        self::assertSame('grant_type=client_credentials&client_id=sdk-client&client_secret=s3cret+value', $server->requests[0]['body']);
        self::assertSame('application/x-www-form-urlencoded', $server->requests[0]['headers']['Content-Type']);
        self::assertSame('https://keelie.example.com/usage-events:report', $server->requests[1]['url']);
        self::assertSame('Bearer token-1', $server->requests[1]['headers']['Authorization']);
        self::assertSame('application/json', $server->requests[1]['headers']['Content-Type']);

        // Mint again 30 seconds before the token expires.
        $clock->now += 271;
        $credential->request('GET', '/ai-catalog');
        self::assertSame(2, $server->minted);
    }

    public function testA401MintsAgainOnce(): void
    {
        $server = new FakeKeelieServer();
        $server->keelieAnswers = [new Response(401), new Response(202)];
        $response = self::credential($server, new Clock())->request('POST', '/usage-events:report', '{}');

        self::assertSame(202, $response->status);
        self::assertSame(2, $server->minted);
        self::assertSame('Bearer token-2', $server->requests[3]['headers']['Authorization']);
    }

    public function testACacheSharesTheTokenAndNeverHoldsTheSecret(): void
    {
        $server = new FakeKeelieServer();
        $cache = new ArrayCache();
        self::credential($server, new Clock(), $cache)->request('GET', '/ai-catalog');
        self::credential($server, new Clock(), $cache)->request('GET', '/ai-catalog');

        self::assertSame(1, $server->minted);
        self::assertStringNotContainsString('s3cret', serialize($cache->values));
    }

    public function testTheSecretAndTheTokenStayOutOfEveryDump(): void
    {
        $server = new FakeKeelieServer();
        $credential = self::credential($server, new Clock());
        $credential->request('GET', '/ai-catalog');
        // The fake keeps what it was sent. A real transport keeps nothing.
        $server->requests = [];
        ob_start();
        var_dump($credential);
        $dumps = [
            (string) ob_get_clean(),
            print_r($credential, true),
            var_export($credential, true),
            var_export((array) $credential, true),
            print_r(get_object_vars($credential), true),
        ];

        foreach ($dumps as $dump) {
            self::assertStringNotContainsString('s3cret', $dump);
            self::assertStringNotContainsString('token-1', $dump);
        }
    }

    public function testTheCredentialCannotBeClonedOrSerialized(): void
    {
        $credential = self::credential(new FakeKeelieServer(), new Clock());
        foreach ([static fn () => clone $credential, static fn () => serialize($credential)] as $copy) {
            try {
                $copy();
                self::fail('a copy was made');
            } catch (\LogicException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testTheSecretStaysOutOfTheTraceOfAFailedMint(): void
    {
        $credential = new SdkCredential(
            'https://keelie.example.com',
            'https://127.0.0.1:1/token',
            'sdk-client',
            's3cret value',
            timeoutSeconds: 0.5,
        );
        try {
            $credential->request('GET', '/ai-catalog');
            self::fail('the mint passed');
        } catch (TransportError $error) {
            // The frames of the SDK. The test's own frames hold the secret it gave.
            $frames = array_filter(
                $error->getTrace(),
                static fn (array $frame): bool => str_starts_with($frame['class'] ?? '', 'Keelie\\')
                    && !str_starts_with($frame['class'] ?? '', 'Keelie\\Tests\\'),
            );
            self::assertNotSame([], $frames);
            self::assertStringNotContainsString('s3cret', print_r($frames, true));
        }
    }

    public function testOneTimeLimitCoversTheMintTheSendAndTheRetry(): void
    {
        $server = new FakeKeelieServer();
        $clock = new Clock();
        // Each answer takes 1.5 seconds, and keelie refuses every token.
        $server->onSend = static function () use ($clock): void {
            $clock->now += 1.5;
        };
        $server->keelieAnswers = [new Response(401), new Response(401)];
        $credential = self::credential($server, $clock);

        try {
            $credential->request('POST', '/usage-events:report', '{}', [], 2.0);
            self::fail('the request passed');
        } catch (TransportError) {
            self::addToAssertionCount(1);
        }

        // The mint got 2 seconds, the send what was left. No time was left for the second mint.
        self::assertSame([2.0, 0.5], array_column($server->requests, 'timeout'));
    }

    public function testTheCurlTransportRefusesAUrlThatIsNotHttp(): void
    {
        $this->expectException(TransportError::class);
        (new CurlTransport())->send('GET', 'file:///etc/passwd');
    }

    public function testTheCatalogIsKeptForSixtySecondsAndNeverServedStale(): void
    {
        $clock = new Clock();
        $keelie = new FakeKeelie([new Response(200, [], '{"v":1}'), new Response(500), new Response(200, [], '{"v":2}')]);
        $catalog = new AiCatalog($keelie, new ProtectedResourceMetadata(Support::RESOURCE, Support::ISSUER), clock: $clock->closure());

        self::assertNull($catalog->answer('/v1/other'));
        self::assertSame('{"v":1}', $catalog->answer(AiCatalog::CATALOG_PATH)?->body);
        self::assertSame('{"v":1}', $catalog->answer(AiCatalog::ARD_PATH)?->body);
        self::assertCount(1, $keelie->requests);

        $clock->now += 60;
        $failed = $catalog->answer(AiCatalog::ARD_PATH);
        self::assertSame(503, $failed?->status);
        self::assertSame(['Retry-After' => '10', 'Cache-Control' => 'no-store'], $failed->headers);
        self::assertStringContainsString('apiable.catalog_fetch_failed status=500', $this->logs->text());

        // keelie is asked again after 10 seconds, not on each request.
        $clock->now += 9;
        self::assertSame(503, $catalog->answer(AiCatalog::ARD_PATH)?->status);
        self::assertCount(2, $keelie->requests);
        $clock->now += 1;
        self::assertSame('{"v":2}', $catalog->answer(AiCatalog::ARD_PATH)?->body);
        self::assertSame(['GET', '/ai-catalog'], [$keelie->requests[2]['method'], $keelie->requests[2]['path']]);
    }

    public function testACacheSharesTheCatalogBetweenProcesses(): void
    {
        $clock = new Clock();
        $cache = new ArrayCache();
        $keelie = new FakeKeelie([new Response(200, [], '{"v":1}')]);
        $metadata = new ProtectedResourceMetadata(Support::RESOURCE, Support::ISSUER);
        (new AiCatalog($keelie, $metadata, $cache, $clock->closure()))->answer(AiCatalog::CATALOG_PATH);
        $second = (new AiCatalog($keelie, $metadata, $cache, $clock->closure()))->answer(AiCatalog::CATALOG_PATH);

        self::assertSame('{"v":1}', $second?->body);
        self::assertCount(1, $keelie->requests);
    }
}
