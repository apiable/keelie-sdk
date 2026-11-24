<?php

declare(strict_types=1);

namespace Keelie\Http;

/** The answer to one HTTP request that the SDK sends. */
final class Response
{
    /**
     * @param array<string, string> $headers the headers, with lowercase names
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers = [],
        public readonly string $body = '',
    ) {
    }

    /** True for a 2xx status. */
    public function ok(): bool
    {
        return $this->status >= 200 && $this->status <= 299;
    }
}
