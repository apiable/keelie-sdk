<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Http\CurlTransport;
use Keelie\Http\Response;
use Keelie\Http\Transport;
use Keelie\Internal\Json;
use Keelie\Internal\JsonObject;
use Psr\SimpleCache\CacheInterface;

/**
 * Talk to keelie with your SDK credential.
 *
 * The usage reporter and the AI Catalog call keelie's API. Each call carries a
 * token of the `sdk_credential` from your signup: it may report usage and read
 * your products, and nothing else. This class mints that token at your issuer
 * with the client credentials grant, keeps it until shortly before it expires, and
 * mints again on a 401.
 *
 * The SDK holds no secret of its own. Read the client id and the secret from the
 * environment, never from source code. Never give it your admin credential.
 *
 * No request that carries the secret or the token follows a redirect. A `307` or
 * `308` would send the same body, and so the secret, to wherever it points. A
 * redirect fails the request instead, as a network error does.
 *
 * Under PHP-FPM, give a PSR-16 `$cache`, so that the processes share one token.
 * Without it, each request that talks to keelie mints a token. The cache then
 * holds the token, which may report usage and read your products until it expires.
 * It never holds the secret.
 */
final class SdkCredential implements KeelieClient
{
    public const TIMEOUT_SECONDS = 10.0;

    private readonly string $base;
    private readonly Transport $http;
    private readonly \Closure $clock;
    private readonly string $form;
    private readonly string $cacheKey;
    private ?string $token = null;
    private float $expiresAt = 0.0;

    /**
     * @param string $keelieUrl the address of keelie: `KEELIE_URL`
     * @param string $tokenUrl the token endpoint of keelie's issuer: `KEELIE_TOKEN_URL`
     * @param string $clientId `sdk_credential.client_id` from the signup answer
     * @param string $clientSecret `sdk_credential.client_secret` from the signup answer
     * @param float $timeoutSeconds how long a call to keelie, or to the token endpoint, waits
     * @param (\Closure(): float)|null $clock seconds since the epoch
     */
    public function __construct(
        string $keelieUrl,
        private readonly string $tokenUrl,
        string $clientId,
        #[\SensitiveParameter] string $clientSecret,
        float $timeoutSeconds = self::TIMEOUT_SECONDS,
        ?Transport $http = null,
        private readonly ?CacheInterface $cache = null,
        ?\Closure $clock = null,
    ) {
        $this->base = rtrim($keelieUrl, '/');
        $this->http = $http ?? new CurlTransport($timeoutSeconds);
        $this->clock = $clock ?? static fn (): float => microtime(true);
        $this->form = http_build_query([
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ], '', '&', PHP_QUERY_RFC1738);
        $this->cacheKey = 'keelie.sdk_token.' . substr(hash('sha256', "{$tokenUrl} {$clientId}"), 0, 32);
    }

    public function request(string $method, string $path, ?string $body = null, array $headers = []): Response
    {
        $token = $this->freshToken(null);
        $response = $this->send($token, $method, $path, $body, $headers);
        if ($response->status !== 401) {
            return $response;
        }

        return $this->send($this->freshToken($token), $method, $path, $body, $headers);
    }

    /** @return array<string, string> the secret and the token stay out of var_dump() and print_r() */
    public function __debugInfo(): array
    {
        return ['keelieUrl' => $this->base, 'tokenUrl' => $this->tokenUrl];
    }

    /** @param array<string, string> $headers */
    private function send(string $token, string $method, string $path, ?string $body, array $headers): Response
    {
        $headers['Authorization'] = "Bearer {$token}";

        return $this->http->send($method, $this->base . $path, $headers, $body);
    }

    /** The token to send. `$refused` is a token keelie answered 401: mint again, unless another process already has. */
    private function freshToken(?string $refused): string
    {
        $now = (float) ($this->clock)();
        if ($this->token === null || $now >= $this->expiresAt || $this->token === $refused) {
            $this->adoptCache($now);
        }
        if ($this->token === null || $now >= $this->expiresAt || $this->token === $refused) {
            $this->mint($now);
        }

        return (string) $this->token;
    }

    private function mint(float $now): void
    {
        $response = $this->http->send('POST', $this->tokenUrl, [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ], $this->form);
        if (!$response->ok()) {
            throw new \RuntimeException("the token endpoint answered {$response->status}");
        }
        try {
            $body = Json::lenient($response->body);
        } catch (\Throwable) {
            $body = null;
        }
        $token = $body instanceof JsonObject ? $body->get('access_token') : null;
        $lifetime = $body instanceof JsonObject ? $body->get('expires_in') : null;
        if (!is_string($token) || !(is_int($lifetime) || is_float($lifetime))) {
            throw new \RuntimeException('the token endpoint answered without a token');
        }
        $this->token = $token;
        // Mint again before the token expires.
        $this->expiresAt = $now + max($lifetime - 30, $lifetime / 2);
        if ($this->cache !== null) {
            try {
                $ttl = max(1, (int) floor($this->expiresAt - $now));
                $this->cache->set($this->cacheKey, ['token' => $token, 'expires_at' => $this->expiresAt], $ttl);
            } catch (\Throwable $error) {
                Log::warning('apiable.cache_failed error=' . Log::errorName($error));
            }
        }
    }

    private function adoptCache(float $now): void
    {
        if ($this->cache === null) {
            return;
        }
        try {
            $state = $this->cache->get($this->cacheKey);
        } catch (\Throwable $error) {
            Log::warning('apiable.cache_failed error=' . Log::errorName($error));

            return;
        }
        if (
            is_array($state) && is_string($state['token'] ?? null)
            && is_float($state['expires_at'] ?? null) && $now < $state['expires_at']
        ) {
            $this->token = $state['token'];
            $this->expiresAt = $state['expires_at'];
        }
    }
}
