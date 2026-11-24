<?php

declare(strict_types=1);

namespace Keelie\Middleware;

use Keelie\InsufficientScope;
use Keelie\Internal\Responses;
use Keelie\ProtectedResourceMetadata;
use Keelie\ScopeMap;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Checks the scope of one route. Add it to the route, after {@see TokenGuard}.
 *
 *     $app->get('/v1/orders/{id}', $handler)
 *         ->add(new ScopeGuard($scopes, $metadata, $responseFactory, '/v1/orders/{id}'));
 *
 * `$route` is the route's template, as it is in the ScopeMap. The method is the
 * request's. A HEAD request is checked as a GET when the map has no HEAD entry for
 * the route: most routers answer a HEAD with the GET handler.
 *
 * A refused token gets 403, `WWW-Authenticate: Bearer error="insufficient_scope",
 * resource_metadata="..."` and an empty body. With no claims on the request, it
 * throws LogicException: TokenGuard did not run first.
 */
final class ScopeGuard implements MiddlewareInterface
{
    private readonly string $refusal;

    public function __construct(
        private readonly ScopeMap $scopes,
        ProtectedResourceMetadata $metadata,
        private readonly ResponseFactoryInterface $responses,
        private readonly string $route,
    ) {
        $this->refusal = $metadata->challenge('insufficient_scope');
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $claims = Guard::claims($request);
        $method = strtoupper($request->getMethod());
        if ($method === 'HEAD' && !$this->scopes->has('HEAD', $this->route)) {
            $method = 'GET';
        }
        try {
            $this->scopes->check($claims, $method, $this->route);
        } catch (InsufficientScope) {
            return Responses::make($this->responses, 403, ['WWW-Authenticate' => $this->refusal]);
        }

        return $handler->handle($request);
    }
}
