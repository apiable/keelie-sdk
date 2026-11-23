<?php

declare(strict_types=1);

namespace Keelie\Internal;

/**
 * A JSON object, as {@see Json} reads it. A PHP array cannot tell `{}` from `[]`.
 *
 * @internal
 */
final class JsonObject
{
    /** @param array<array-key, mixed> $members */
    public function __construct(public readonly array $members)
    {
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->members);
    }

    public function get(string $name): mixed
    {
        return $this->members[$name] ?? null;
    }
}
