<?php

declare(strict_types=1);

namespace Keelie\Http;

/**
 * The SDK's own HTTP client, with ext-curl.
 *
 * It follows no redirect. A 3xx answer throws {@see TransportError}, as a network
 * error does: a `307` or `308` would send the same body, and so a secret, to the
 * address it names. Only `http` and `https` URLs are sent.
 */
final class CurlTransport implements Transport
{
    public function __construct(private readonly float $timeoutSeconds = 5.0)
    {
    }

    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter] array $headers = [],
        #[\SensitiveParameter] ?string $body = null,
        ?float $timeoutSeconds = null,
    ): Response {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new TransportError('not an http or https URL');
        }
        $curl = curl_init($url);
        if ($curl === false) {
            throw new TransportError('curl_init failed');
        }
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }
        $answerHeaders = [];
        $seconds = $timeoutSeconds === null ? $this->timeoutSeconds : min($this->timeoutSeconds, $timeoutSeconds);
        $timeout = max(1, (int) ceil($seconds * 1000));
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT_MS => $timeout,
            CURLOPT_TIMEOUT_MS => $timeout,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$answerHeaders): int {
                $colon = strpos($line, ':');
                if ($colon !== false) {
                    $answerHeaders[strtolower(trim(substr($line, 0, $colon)))] = trim(substr($line, $colon + 1));
                }

                return strlen($line);
            },
        ]);
        if ($body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        if ($method === 'HEAD') {
            curl_setopt($curl, CURLOPT_NOBODY, true);
        }
        $answer = curl_exec($curl);
        if ($answer === false) {
            $error = curl_errno($curl);
            throw new TransportError("curl error {$error}");
        }
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if ($status >= 300 && $status <= 399) {
            throw new TransportError("redirect {$status}");
        }

        return new Response($status, $answerHeaders, is_string($answer) ? $answer : '');
    }
}
