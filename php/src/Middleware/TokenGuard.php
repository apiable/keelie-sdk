<?php

declare(strict_types=1);

namespace Keelie\Middleware;

use Keelie\Claims;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The guard for a REST API: it checks the token, and gives the claims to your
 * routes in the request attribute `keelie.claims`.
 *
 *     $app->add(new TokenGuard($verifier, $metadata, $responseFactory));
 *
 * It does not check the scope. Middleware for the whole app often runs before the
 * router, so it cannot see the route template. Check the scope on each route, with
 * {@see ScopeGuard} or {@see \Keelie\ScopeMap::check()}. A route without it is
 * authenticated, but it has no scope check.
 */
final class TokenGuard extends Guard
{
    protected function handle(
        Claims $claims,
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        return $handler->handle($request);
    }
}
