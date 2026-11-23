<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\Log;
use Keelie\Middleware\McpGuard;
use Keelie\ProtectedResourceMetadata;
use Keelie\SigningKeys;
use Keelie\TokenVerifier;
use Keelie\UsageReporter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class McpTest extends TestCase
{
    private const MCP = 'https://api.example.com/mcp';

    private FakeKeelie $keelie;
    private UsageReporter $reporter;
    private McpGuard $guard;
    private ProtectedResourceMetadata $metadata;

    protected function setUp(): void
    {
        Support::logs();
        $this->metadata = new ProtectedResourceMetadata(self::MCP, Support::ISSUER);
        $verifier = new TokenVerifier(
            Support::ISSUER,
            self::MCP,
            Support::ORG_ID,
            new SigningKeys(Support::ISSUER, new FakeIssuer([Support::pair()])),
        );
        $this->keelie = new FakeKeelie();
        $this->reporter = new UsageReporter($this->keelie, sendAtShutdown: false);
        $this->guard = new McpGuard(
            $verifier,
            $this->metadata,
            Support::factory(),
            Support::factory(),
            ['classify' => 'classify:run', 'get_order' => 'orders:read'],
            $this->reporter,
            maxBodyBytes: 4096,
        );
    }

    protected function tearDown(): void
    {
        Log::setLogger(null);
    }

    private function post(string $body, App $app = new App(), ?string $token = null): ResponseInterface
    {
        $token ??= Support::token(['aud' => self::MCP, 'scope' => 'orders:read']);

        return $this->guard->process(Support::request('POST', self::MCP, $token, $body), $app);
    }

    /** @return array<string, mixed> */
    private static function error(ResponseInterface $response): array
    {
        return json_decode((string) $response->getBody(), true);
    }

    public function testAToolCallWithItsScopeReachesTheServerAndIsReported(): void
    {
        $body = '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_order","arguments":{}}}';
        $app = new App();
        $response = $this->post($body, $app, Support::token([
            'aud' => self::MCP,
            'scope' => 'orders:read',
            'consumer_id' => Support::CONSUMER_ID,
        ]));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('app:' . $body, (string) $response->getBody());
        $this->reporter->flush();
        $event = $this->keelie->events(0)[0];
        self::assertSame('get_order', $event['capability_key']);
        self::assertSame('tool_call', $event['unit']);
        self::assertSame('consumer-client', $event['client_id']);
        self::assertSame(Support::CONSUMER_ID, $event['consumer_id']);
        self::assertArrayNotHasKey('credits', $event);
    }

    public function testAToolCallTheServerFailsIsNotReported(): void
    {
        $this->post('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_order"}}', new App(500));

        self::assertSame(0, $this->reporter->buffered());
    }

    public function testAToolWithoutItsScopeIsRefusedAndTheAnswerDoesNotNameTheScope(): void
    {
        foreach (['classify', 'unknown_tool'] as $tool) {
            $response = $this->post('{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"' . $tool . '"}}');

            self::assertSame(403, $response->getStatusCode());
            self::assertSame($this->metadata->challenge('insufficient_scope'), $response->getHeaderLine('WWW-Authenticate'));
            self::assertSame(
                ['jsonrpc' => '2.0', 'id' => 'a', 'error' => ['code' => -31001, 'message' => 'Insufficient scope']],
                self::error($response),
            );
        }
    }

    public function testOtherMethodsPassWithNoScopeCheck(): void
    {
        foreach (['initialize', 'tools/list', 'notifications/initialized', 'ping'] as $method) {
            self::assertSame(200, $this->post('{"jsonrpc":"2.0","id":1,"method":"' . $method . '"}')->getStatusCode());
        }
        self::assertSame(0, $this->reporter->buffered());
    }

    /** @return iterable<string, array{string, int, int}> */
    public static function badBodies(): iterable
    {
        yield 'not JSON' => ['{', 400, -32700];
        yield 'not UTF-8' => ["{\"method\":\"\xff\"}", 400, -32700];
        yield 'too deep' => [str_repeat('[', 1001) . str_repeat(']', 1001), 400, -32700];
        yield 'a batch' => ['[{"jsonrpc":"2.0","id":1,"method":"ping"}]', 400, -32600];
        yield 'not an object' => ['"ping"', 400, -32600];
        yield 'a key given twice' => ['{"method":"tools/call","method":"ping","id":1}', 400, -32600];
        yield 'a key given twice, escaped' => ['{"params":{"name":"get_order","name":"classify"},"method":"tools/call","id":1}', 400, -32600];
        yield 'a tool call with no id' => ['{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_order"}}', 400, -32600];
        yield 'a tool name that is not a string' => ['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}', 400, -32602];
        yield 'too large' => ['{"x":"' . str_repeat('a', 5000) . '"}', 413, -32600];
    }

    #[DataProvider('badBodies')]
    public function testABodyTheGuardCannotReadIsRefused(string $body, int $status, int $code): void
    {
        $app = new App();
        $response = $this->post($body, $app);

        self::assertSame($status, $response->getStatusCode());
        self::assertSame($code, self::error($response)['error']['code']);
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertNull($app->request);
    }

    public function testGetHeadAndDeletePassAndOtherMethodsGet405(): void
    {
        $token = Support::token(['aud' => self::MCP]);
        foreach (['GET', 'HEAD', 'DELETE'] as $method) {
            self::assertSame(200, $this->guard->process(Support::request($method, self::MCP, $token), new App())->getStatusCode());
        }
        $put = $this->guard->process(Support::request('PUT', self::MCP, $token, '{}'), new App());
        self::assertSame(405, $put->getStatusCode());
        self::assertSame('GET, POST, DELETE', $put->getHeaderLine('Allow'));
    }

    public function testARequestWithNoTokenIsRefusedBeforeTheBodyIsRead(): void
    {
        $response = $this->guard->process(Support::request('POST', self::MCP, null, '{'), new App());

        self::assertSame(401, $response->getStatusCode());
    }
}
