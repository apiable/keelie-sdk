<?php

declare(strict_types=1);

namespace Keelie;

/**
 * The token does not carry the scope the route requires. Answer it with 403, not
 * 401: the token is good, it does not allow this call.
 */
final class InsufficientScope extends \RuntimeException
{
    public function __construct(public readonly string $method, public readonly string $route)
    {
        parent::__construct("{$method} {$route}");
    }
}
