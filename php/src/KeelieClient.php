<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Http\Response;
use Keelie\Http\TransportError;

/**
 * Sends one request to keelie, with the auth of your SDK credential.
 *
 * {@see SdkCredential} is the one to use. {@see UsageReporter} and
 * {@see AiCatalog} need nothing else from it, so a test gives them its own.
 */
interface KeelieClient
{
    /**
     * @param string $path keelie's path, such as `/usage-events:report`. The base URL and the auth are the client's own.
     * @param array<string, string> $headers
     * @param float|null $timeoutSeconds the longest the whole call may take, a new token included.
     *                                   Null: the client's own limit for each step.
     *
     * @throws TransportError for a network error, a timeout or a redirect
     * @throws \RuntimeException when the client cannot get a token
     */
    public function request(
        string $method,
        string $path,
        ?string $body = null,
        array $headers = [],
        ?float $timeoutSeconds = null,
    ): Response;
}
