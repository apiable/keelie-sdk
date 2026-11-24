<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Internal\PyText;

/**
 * The scope that each route requires.
 *
 * You give the SDK one map: for each route, the scope a token must carry. A route
 * is the HTTP method and the path template your router matched, such as
 * `"GET /v1/orders/{id}"`. Give the template, not the path of the request, so that
 * one entry covers every order.
 *
 * The check is strict:
 *
 * - A scope matches only itself. `orders:read` does not grant `orders`, and
 *   `orders` does not grant `orders:read`.
 * - A route matches only itself. There is no prefix and no wildcard.
 * - A route that is not in the map is refused. Add every route that a token may call.
 */
final class ScopeMap
{
    /** @var array<string, string> the scope of each "METHOD\0route" */
    private array $routes = [];

    /**
     * `$routes` maps each `"METHOD /template"` to its one scope, such as
     * `['GET /v1/orders/{id}' => 'orders:read']`. The method and the template are
     * split at the first space.
     *
     * @param array<string, string> $routes
     *
     * @throws \InvalidArgumentException when a key is not a method and a template, a
     *                                   value is not exactly one scope, or a route is given twice
     */
    public function __construct(array $routes)
    {
        foreach ($routes as $entry => $scope) {
            $entry = (string) $entry;
            $at = strpos($entry, ' ');
            if ($at === false || $at === 0 || $at === strlen($entry) - 1) {
                throw new \InvalidArgumentException('not "METHOD /route": ' . json_encode($entry));
            }
            $this->add(substr($entry, 0, $at), substr($entry, $at + 1), $scope);
        }
    }

    /**
     * @internal A map from pairs that are already split, such as `['tools/call', $toolName, $scope]`.
     *
     * @param iterable<array{string, string, mixed}> $pairs
     */
    public static function fromPairs(iterable $pairs): self
    {
        $map = new self([]);
        foreach ($pairs as [$method, $route, $scope]) {
            $map->add($method, $route, $scope);
        }

        return $map;
    }

    /**
     * Return if the token may call the route.
     *
     * @throws InsufficientScope when the token lacks the route's scope, or the route is not in the map
     */
    public function check(Claims $claims, string $method, string $route): void
    {
        $method = strtoupper($method);
        $required = $this->routes[self::key($method, $route)] ?? null;
        if ($required !== null && $claims->hasScope($required)) {
            return;
        }
        // A route that is not in the map can come from the request, such as an MCP
        // tool name, and stays out of the log.
        Log::info(sprintf(
            'apiable.scope_refused reason=%s client=%s method=%s route=%s',
            $required === null ? 'unmapped' : 'scope',
            $claims->azp,
            $method,
            $required === null ? '-' : $route,
        ));
        throw new InsufficientScope($method, $route);
    }

    /** @internal True if the map has this route. */
    public function has(string $method, string $route): bool
    {
        return isset($this->routes[self::key(strtoupper($method), $route)]);
    }

    private function add(string $method, string $route, mixed $scope): void
    {
        if (!PyText::isOneScope($scope)) {
            throw new \InvalidArgumentException('not one scope: ' . json_encode($scope) . " for {$method} {$route}");
        }
        $key = self::key(strtoupper($method), $route);
        if (isset($this->routes[$key])) {
            throw new \InvalidArgumentException("route given twice: {$method} {$route}");
        }
        $this->routes[$key] = $scope;
    }

    private static function key(string $method, string $route): string
    {
        return "{$method}\0{$route}";
    }
}
