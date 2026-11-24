<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\AiCatalog;
use Keelie\Claims;
use Keelie\Http\Response;
use Keelie\Log;
use Keelie\Middleware\AiCatalogMiddleware;
use Keelie\Middleware\Guard;
use Keelie\Middleware\ScopeGuard;
use Keelie\Middleware\TokenGuard;
use Keelie\ProtectedResourceMetadata;
use Keelie\ScopeMap;
use Keelie\TokenVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class MiddlewareTest extends TestCase
{
    private ProtectedResourceMetadata $metadata;
    private TokenGuard $guard;

    protected function setUp(): void
    {
        Support::logs();
        $this->metadata = new ProtectedResourceMetadata(Support::RESOURCE, Support::ISSUER);
        $this->guard = new TokenGuard(Support::verifier(), $this->metadata, Support::factory());
    }

    protected function tearDown(): void
    {
        Log::setLogger(null);
    }

    /** Run `$request` through each middleware in turn, then the app. */
    private static function through(ServerRequestInterface $request, App $app, MiddlewareInterface ...$middleware): ResponseInterface
    {
        $handler = array_reduce(
            array_reverse($middleware),
            static fn (RequestHandlerInterface $next, MiddlewareInterface $layer): RequestHandlerInterface => new class ($layer, $next) implements RequestHandlerInterface {
                public function __construct(private MiddlewareInterface $layer, private RequestHandlerInterface $next)
                {
                }

                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    return $this->layer->process($request, $this->next);
                }
            },
            $app,
        );

        return $handler->handle($request);
    }

    public function testAGoodTokenReachesTheRouteWithItsClaims(): void
    {
        $app = new App();
        $response = self::through(Support::request('GET', 'https://api.example.com/v1/orders/42', Support::token()), $app, $this->guard);

        self::assertSame(200, $response->getStatusCode());
        self::assertInstanceOf(ServerRequestInterface::class, $app->request);
        self::assertSame('consumer-client', TokenGuard::claims($app->request)->azp);
    }

    public function testARequestWithNoTokenIsToldWhereToGetOne(): void
    {
        $app = new App();
        $response = self::through(Support::request('GET', 'https://api.example.com/v1/orders/42'), $app, $this->guard);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame($this->metadata->challenge(), $response->getHeaderLine('WWW-Authenticate'));
        self::assertNull($app->request);
    }

    public function testEveryRefusedTokenGetsTheSameAnswer(): void
    {
        $answers = [];
        foreach ([Support::token(['exp' => time() - 300]), Support::token(['org_id' => Support::CONSUMER_ID]), 'not.a.token'] as $token) {
            $response = self::through(Support::request('GET', 'https://api.example.com/v1/a', $token), new App(), $this->guard);
            $answers[] = [$response->getStatusCode(), $response->getHeaderLine('WWW-Authenticate'), (string) $response->getBody()];
        }

        self::assertSame([[401, $this->metadata->challenge('invalid_token'), '']], array_values(array_unique($answers, SORT_REGULAR)));
    }

    public function testTwoAuthorizationHeadersAreNoToken(): void
    {
        $request = Support::request('GET', 'https://api.example.com/v1/a', Support::token())
            ->withAddedHeader('Authorization', 'Bearer other');
        $response = self::through($request, new App(), $this->guard);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame($this->metadata->challenge(), $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testTheMetadataIsServedWithNoToken(): void
    {
        $response = self::through(Support::request('GET', 'https://api.example.com/.well-known/oauth-protected-resource/v1'), new App(), $this->guard);
        $head = self::through(Support::request('HEAD', 'https://api.example.com/.well-known/oauth-protected-resource/v1'), new App(), $this->guard);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame($this->metadata->document, (string) $response->getBody());
        self::assertSame(200, $head->getStatusCode());
        self::assertSame('', (string) $head->getBody());
        self::assertSame((string) strlen($this->metadata->document), $head->getHeaderLine('Content-Length'));

        // A read that a header turns into a POST is not served as the metadata.
        $app = new App();
        $post = Support::request('GET', 'https://api.example.com/.well-known/oauth-protected-resource/v1')
            ->withHeader('X-HTTP-Method', 'post');
        self::through($post, $app, $this->guard);
        self::assertNotNull($app->request);
    }

    public function testARealPreflightUnderTheResourcePassesUntouched(): void
    {
        $app = new App();
        $request = Support::request('OPTIONS', 'https://api.example.com/v1/orders/1')
            ->withHeader('Origin', 'https://app.example.com')
            ->withHeader('Access-Control-Request-Method', 'DELETE');
        $response = self::through($request, $app, $this->guard);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame($request, $app->request);
    }

    public function testPathsOutsideTheResourceAndAPreflightPassUntouched(): void
    {
        foreach ([['GET', '/health'], ['GET', '/v10'], ['OPTIONS', '/v1/orders']] as [$method, $path]) {
            $app = new App();
            $request = Support::request($method, "https://api.example.com{$path}")
                ->withHeader('Origin', 'https://app.example.com')
                ->withHeader('Access-Control-Request-Method', 'GET');
            $response = self::through($request, $app, $this->guard);
            self::assertSame(200, $response->getStatusCode(), "{$method} {$path}");
            self::assertNull($app->request?->getAttribute(Guard::CLAIMS_ATTRIBUTE));
        }
    }

    /** @return iterable<string, array{string, string, array<string, string>}> */
    public static function notPreflights(): iterable
    {
        $origin = 'https://app.example.com';
        yield 'an OPTIONS with no preflight header' => ['OPTIONS', '/v1/orders/1', []];
        yield 'an OPTIONS with no Origin' => ['OPTIONS', '/v1/orders/1', ['Access-Control-Request-Method' => 'GET']];
        yield 'an OPTIONS with no Access-Control-Request-Method' => ['OPTIONS', '/v1/orders/1', ['Origin' => $origin]];
        yield 'a preflight that overrides its method' => ['OPTIONS', '/v1/orders/1', ['Origin' => $origin, 'Access-Control-Request-Method' => 'GET', 'X-HTTP-Method-Override' => 'DELETE']];
        yield 'a preflight with an override to OPTIONS' => ['OPTIONS', '/v1/orders/1', ['Origin' => $origin, 'Access-Control-Request-Method' => 'GET', 'X-HTTP-Method' => 'OPTIONS']];
        yield 'another override header' => ['OPTIONS', '/v1/orders/1', ['Origin' => $origin, 'Access-Control-Request-Method' => 'GET', 'X-Method-Override' => 'PUT']];
    }

    /** @param array<string, string> $headers */
    #[DataProvider('notPreflights')]
    public function testOnlyAPreflightOrAReadOfTheMetadataPassesWithNoToken(string $method, string $path, array $headers): void
    {
        $request = Support::request($method, "https://api.example.com{$path}");
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        $app = new App();
        $response = self::through($request, $app, $this->guard);

        self::assertSame(401, $response->getStatusCode());
        self::assertNull($app->request);
    }

    /** @return iterable<string, array{string}> */
    public static function otherForms(): iterable
    {
        yield 'upper case' => ['/V1/orders'];
        yield 'an escape' => ['/%76%31/orders'];
        yield 'a dot segment' => ['/x/../v1/orders'];
        yield 'a doubled slash' => ['//v1/orders'];
        yield 'a backslash' => ['/v1\\orders'];
        yield 'a format extension' => ['/v1.json'];
        yield 'a long path with an escape' => ['/' . str_repeat('a', 300) . '/%2e%2e/v1'];
    }

    #[DataProvider('otherForms')]
    public function testAPathARouterCouldReadAsTheResourceIsGuarded(string $path): void
    {
        $response = self::through(Support::request('GET', "https://api.example.com{$path}"), new App(), $this->guard);

        self::assertSame(401, $response->getStatusCode());
    }

    public function testTheGuardRefusesAVerifierForAnotherAudience(): void
    {
        $verifier = new TokenVerifier(Support::ISSUER, 'https://api.example.com/v2', Support::ORG_ID);

        $this->expectException(\InvalidArgumentException::class);
        new TokenGuard($verifier, $this->metadata, Support::factory());
    }

    public function testTheScopeGuardChecksItsRoute(): void
    {
        $scopes = new ScopeMap(['GET /v1/orders/{id}' => 'orders:read', 'DELETE /v1/orders/{id}' => 'orders:write']);
        $read = new ScopeGuard($scopes, $this->metadata, Support::factory(), '/v1/orders/{id}');

        $get = self::through(Support::request('GET', 'https://api.example.com/v1/orders/42', Support::token()), new App(), $this->guard, $read);
        $head = self::through(Support::request('HEAD', 'https://api.example.com/v1/orders/42', Support::token()), new App(), $this->guard, $read);
        $delete = self::through(Support::request('DELETE', 'https://api.example.com/v1/orders/42', Support::token()), new App(), $this->guard, $read);

        self::assertSame(200, $get->getStatusCode());
        self::assertSame(200, $head->getStatusCode());
        self::assertSame(403, $delete->getStatusCode());
        self::assertSame($this->metadata->challenge('insufficient_scope'), $delete->getHeaderLine('WWW-Authenticate'));
        self::assertSame('', (string) $delete->getBody());
    }

    public function testTheScopeGuardWithoutTheTokenGuardIsAnError(): void
    {
        $scopes = new ScopeMap(['GET /a' => 'a']);

        $this->expectException(\LogicException::class);
        self::through(Support::request('GET', 'https://api.example.com/a'), new App(), new ScopeGuard($scopes, $this->metadata, Support::factory(), '/a'));
    }

    public function testTheCatalogIsServedWithNoTokenOnceItIsMade(): void
    {
        $catalogPath = 'https://api.example.com/.well-known/ai-catalog.json';
        $root = new ProtectedResourceMetadata('https://api.example.com', Support::ISSUER);
        $guard = new TokenGuard(
            new TokenVerifier(Support::ISSUER, 'https://api.example.com', Support::ORG_ID),
            $root,
            Support::factory(),
        );
        // Before an AiCatalog is made, the path is guarded like any other.
        self::assertSame(401, self::through(Support::request('GET', $catalogPath), new App(), $guard)->getStatusCode());

        $keelie = new FakeKeelie([new Response(200, [], '{"entries":[]}')]);
        $catalog = new AiCatalogMiddleware(new AiCatalog($keelie, $root), Support::factory());
        $response = self::through(Support::request('GET', $catalogPath), new App(), $guard, $catalog);
        $ard = self::through(Support::request('GET', 'https://api.example.com/.well-known/ard.json'), new App(), $catalog, $guard);
        $post = self::through(Support::request('POST', $catalogPath), new App(), $guard, $catalog);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/ai-catalog+json', $response->getHeaderLine('Content-Type'));
        self::assertSame('max-age=60', $response->getHeaderLine('Cache-Control'));
        self::assertSame('{"entries":[]}', (string) $response->getBody());
        self::assertSame('application/json', $ard->getHeaderLine('Content-Type'));
        self::assertSame(401, $post->getStatusCode());
        self::assertCount(1, $keelie->requests);
    }

    public function testTheClaimsHelperNeedsAGuard(): void
    {
        $this->expectException(\LogicException::class);
        Guard::claims(Support::request('GET', 'https://api.example.com/v1'));
    }

    public function testClaimsAreReadOnly(): void
    {
        $claims = new Claims('a', Support::ORG_ID, [], null, new \DateTimeImmutable(), null);

        $this->expectException(\Error::class);
        $claims->azp = 'b'; // @phpstan-ignore-line
    }
}
