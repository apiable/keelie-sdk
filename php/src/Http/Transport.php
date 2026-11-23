<?php

declare(strict_types=1);

namespace Keelie\Http;

/**
 * Sends one HTTP request for the SDK, and returns the answer.
 *
 * {@see CurlTransport} is the one the SDK uses where you give none. A test gives
 * its own, which answers with no network.
 *
 * A Transport must not follow a redirect. The SDK fetches keys only from the
 * addresses the issuer names, and sends a secret or a token only to the address
 * you gave it.
 */
interface Transport
{
    /**
     * @param array<string, string> $headers they can hold a token: keep them out of a log
     * @param string|null $body it can hold a secret: keep it out of a log
     * @param float|null $timeoutSeconds the longest this call may take, if less than the transport's own limit
     *
     * @throws TransportError for a network error, a timeout or a redirect
     */
    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter] array $headers = [],
        #[\SensitiveParameter] ?string $body = null,
        ?float $timeoutSeconds = null,
    ): Response;
}
