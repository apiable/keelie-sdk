<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\Claims;
use Keelie\InsufficientScope;
use Keelie\Log;
use Keelie\ProtectedResourceMetadata;
use Keelie\ScopeMap;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ScopesAndDiscoveryTest extends TestCase
{
    protected function setUp(): void
    {
        Support::logs();
    }

    protected function tearDown(): void
    {
        Log::setLogger(null);
    }

    /** @param list<string> $scopes */
    private static function claims(array $scopes): Claims
    {
        return new Claims('client', Support::ORG_ID, $scopes, null, new \DateTimeImmutable(), null);
    }

    public function testAScopeMatchesOnlyItselfOnItsOwnRoute(): void
    {
        $scopes = new ScopeMap(['GET /v1/orders/{id}' => 'orders:read']);
        $scopes->check(self::claims(['orders:read']), 'get', '/v1/orders/{id}');

        foreach ([
            [['orders'], 'GET', '/v1/orders/{id}'],
            [['orders:read:all'], 'GET', '/v1/orders/{id}'],
            [['orders:read'], 'POST', '/v1/orders/{id}'],
            [['orders:read'], 'GET', '/v1/orders'],
        ] as [$granted, $method, $route]) {
            try {
                $scopes->check(self::claims($granted), $method, $route);
                self::fail("{$method} {$route} passed");
            } catch (InsufficientScope $refused) {
                self::assertSame($route, $refused->route);
            }
        }
    }

    public function testAnUnmappedRouteStaysOutOfTheLog(): void
    {
        $logs = Support::logs();
        $scopes = new ScopeMap(['GET /a' => 'a']);
        try {
            $scopes->check(self::claims(['a']), 'GET', '/secret-from-the-request');
        } catch (InsufficientScope) {
        }

        self::assertStringContainsString('apiable.scope_refused reason=unmapped client=client method=GET route=-', $logs->text());
        self::assertStringNotContainsString('secret', $logs->text());
    }

    /** @return iterable<string, array{array<string, string>}> */
    public static function badMaps(): iterable
    {
        yield 'no space' => [['GET/a' => 'a']];
        yield 'no route' => [['GET ' => 'a']];
        yield 'two scopes' => [['GET /a' => 'a b']];
        yield 'an empty scope' => [['GET /a' => '']];
        yield 'given twice' => [['GET /a' => 'a', 'get /a' => 'b']];
    }

    /** @param array<string, string> $routes */
    #[DataProvider('badMaps')]
    public function testABadMapIsRefusedWhenItIsMade(array $routes): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ScopeMap($routes);
    }

    public function testTheMetadataNamesTheResourceAndTheIssuer(): void
    {
        $metadata = new ProtectedResourceMetadata(Support::RESOURCE, Support::ISSUER, ['orders:read']);

        self::assertSame('/.well-known/oauth-protected-resource/v1', $metadata->path);
        self::assertSame('https://api.example.com/.well-known/oauth-protected-resource/v1', $metadata->url);
        self::assertSame([
            'resource' => Support::RESOURCE,
            'authorization_servers' => [Support::ISSUER],
            'bearer_methods_supported' => ['header'],
            'scopes_supported' => ['orders:read'],
        ], json_decode($metadata->document, true));
        self::assertSame('Bearer resource_metadata="' . $metadata->url . '"', $metadata->challenge());
        self::assertSame(
            'Bearer error="invalid_token", resource_metadata="' . $metadata->url . '"',
            $metadata->challenge('invalid_token'),
        );
    }

    public function testAResourceAtTheRootServesTheMetadataAtTheWellKnownPath(): void
    {
        $metadata = new ProtectedResourceMetadata('https://api.example.com', Support::ISSUER);

        self::assertSame('/.well-known/oauth-protected-resource', $metadata->path);
        self::assertTrue($metadata->protects('/anything'));
    }

    /** @return iterable<string, array{string}> */
    public static function badResources(): iterable
    {
        yield 'http' => ['http://api.example.com/v1'];
        yield 'a query' => ['https://api.example.com/v1?a=1'];
        yield 'a fragment' => ['https://api.example.com/v1#a'];
        yield 'a final slash' => ['https://api.example.com/v1/'];
        yield 'a user' => ['https://me@api.example.com/v1'];
        yield 'an uppercase host' => ['https://API.example.com/v1'];
        yield 'an uppercase scheme' => ['HTTPS://api.example.com/v1'];
        yield 'a port that is not a number' => ['https://api.example.com:x/v1'];
        yield 'a space' => ['https://api.example.com/v 1'];
        yield 'no host' => ['https:///v1'];
    }

    #[DataProvider('badResources')]
    public function testAResourceThatKeelieWouldNotStoreIsRefused(string $resource): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ProtectedResourceMetadata($resource, Support::ISSUER);
    }

    public function testAnErrorCodeOutsideRfc6750IsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new ProtectedResourceMetadata(Support::RESOURCE, Support::ISSUER))->challenge('bad", x="y');
    }

    public function testTheBearerTokenIsReadFromTheHeader(): void
    {
        self::assertSame('abc', ProtectedResourceMetadata::bearerToken('Bearer abc'));
        self::assertSame('abc', ProtectedResourceMetadata::bearerToken('  bearer   abc '));
        self::assertNull(ProtectedResourceMetadata::bearerToken('Basic abc'));
        self::assertNull(ProtectedResourceMetadata::bearerToken('Bearer'));
        self::assertNull(ProtectedResourceMetadata::bearerToken(null));
    }
}
