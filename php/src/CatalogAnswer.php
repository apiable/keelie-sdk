<?php

declare(strict_types=1);

namespace Keelie;

/** What to answer a GET or a HEAD of a catalog path. */
final class CatalogAnswer
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }
}
