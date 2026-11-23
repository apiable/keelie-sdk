<?php

declare(strict_types=1);

namespace Keelie\Middleware;

use Keelie\Claims;
use Keelie\Internal\PathForms;
use Keelie\Internal\Responses;
use Keelie\ProtectedResourceMetadata;
use Keelie\TokenRejected;
use Keelie\TokenVerifier;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The part every token guard shares. A guard adds only what it does with the claims.
 *
 * Every guard refuses a token in the same way: 401, an empty body, and
 * `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`. The
 * answer is the same for every reason. The reason goes to your log only.
 *
 * Each guard also serves the RFC 9728 metadata at `$metadata->path`, with no token,
 * and refuses a request with no token with 401 and
 * `WWW-Authenticate: Bearer resource_metadata="..."`, so an agent can find your
 * issuer. Paths outside `resource` and a CORS preflight pass untouched. A CORS
 * preflight is an OPTIONS request with an `Access-Control-Request-Method` header.
 * Any other OPTIONS request needs a token.
 *
 * A framework can read the method from a header, such as Slim's
 * `MethodOverrideMiddleware` and Symfony do. So the guard reads those headers too
 * ({@see METHOD_OVERRIDE_HEADERS}). A request passes without a token only if it
 * passes as its own method and as each method the headers name.
 *
 * The verifier's audience must be the `resource` of the metadata, or the guard
 * throws when you make it. An agent asks keelie for a token with that `resource`
 * (RFC 8707), and keelie writes it into `aud`.
 */
abstract class Guard implements MiddlewareInterface
{
    /** The request attribute that holds the claims of a verified token. */
    public const CLAIMS_ATTRIBUTE = 'keelie.claims';
    /** The headers a framework can read as the method of the request. */
    public const METHOD_OVERRIDE_HEADERS = ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override'];

    private readonly string $challenge;
    private readonly string $refusal;

    public function __construct(
        private readonly TokenVerifier $verifier,
        protected readonly ProtectedResourceMetadata $metadata,
        protected readonly ResponseFactoryInterface $responses,
    ) {
        if ($verifier->audience !== $metadata->resource) {
            throw new \InvalidArgumentException(sprintf(
                "the verifier's audience %s is not the resource %s: give both the same value",
                json_encode($verifier->audience, JSON_UNESCAPED_SLASHES),
                json_encode($metadata->resource, JSON_UNESCAPED_SLASHES),
            ));
        }
        $this->challenge = $metadata->challenge();
        $this->refusal = $metadata->challenge('invalid_token');
    }

    /**
     * The claims a guard put on the request.
     *
     * @throws \LogicException when no guard checked the request: a route that
     *                         needs a token is not behind a guard
     */
    public static function claims(ServerRequestInterface $request): Claims
    {
        $claims = $request->getAttribute(self::CLAIMS_ATTRIBUTE);
        if (!$claims instanceof Claims) {
            throw new \LogicException('no claims on the request: put the route behind TokenGuard');
        }

        return $claims;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = $request->getMethod();
        $methods = self::methods($request);
        $path = $request->getUri()->getPath();
        $path = $path === '' ? '/' : $path;
        if ($methods === ['OPTIONS'] && $request->hasHeader('Access-Control-Request-Method')) {
            // A CORS preflight carries no token, and your CORS middleware answers it.
            return $handler->handle($request);
        }
        if ($path === $this->metadata->path && array_diff($methods, ['GET', 'HEAD']) === []) {
            // Before the token check: with a resource at the root, the metadata is
            // under it, and the agent reads it with no token.
            return Responses::make(
                $this->responses,
                200,
                ['Content-Type' => 'application/json'],
                $this->metadata->document,
                $method === 'HEAD',
            );
        }
        if (!PathForms::guarded($methods, $path, $this->metadata)) {
            return $handler->handle($request);
        }

        $authorization = $request->getHeader('Authorization');
        $token = count($authorization) === 1 ? ProtectedResourceMetadata::bearerToken($authorization[0]) : null;
        if ($token === null) {
            return Responses::make($this->responses, 401, ['WWW-Authenticate' => $this->challenge]);
        }
        try {
            $claims = $this->verifier->verify($token);
        } catch (TokenRejected) {
            return Responses::make($this->responses, 401, ['WWW-Authenticate' => $this->refusal]);
        }

        return $this->handle($claims, $request->withAttribute(self::CLAIMS_ATTRIBUTE, $claims), $handler);
    }

    /**
     * The request's method, and each method an override header names, in upper case.
     *
     * @return list<string>
     */
    protected static function methods(ServerRequestInterface $request): array
    {
        $methods = [$request->getMethod()];
        foreach (self::METHOD_OVERRIDE_HEADERS as $name) {
            foreach ($request->getHeader($name) as $value) {
                $methods[] = strtoupper(trim($value));
            }
        }

        return array_values(array_unique($methods));
    }

    /** Serve a request whose token verified. */
    abstract protected function handle(
        Claims $claims,
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface;
}
