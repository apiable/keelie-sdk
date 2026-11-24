<?php

declare(strict_types=1);

namespace Keelie;

/**
 * The token does not verify. `$reason` is for your log, never for the caller.
 *
 * The reason is one of `malformed`, `algorithm`, `kid`, `keys_unavailable`,
 * `signature`, `expired`, `not_yet_valid`, `issuer`, `audience`, `claims`, `org`
 * and `typ`.
 */
final class TokenRejected extends \RuntimeException
{
    public function __construct(public readonly string $reason, ?\Throwable $previous = null)
    {
        parent::__construct($reason, 0, $previous);
    }
}
