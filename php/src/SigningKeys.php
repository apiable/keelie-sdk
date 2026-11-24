<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Http\CurlTransport;
use Keelie\Http\Transport;
use Keelie\Internal\Base64Url;
use Keelie\Internal\Json;
use Keelie\Internal\JsonObject;
use Psr\SimpleCache\CacheInterface;

/**
 * The issuer's RS256 signing keys.
 *
 * The first token fetches the key set: the issuer's discovery document names its
 * `jwks_uri`, and that document holds the keys. A `kid` the cache does not know
 * fetches once more, then is refused. That is how a rotated key is picked up
 * without a restart: the first token it signs fetches it.
 *
 * Once a key set is in hand, at most one fetch a minute, however many unknown
 * `kid` values arrive and whether or not the fetch succeeds. A flood of made-up
 * `kid` values costs the issuer one request a minute, also while the issuer is
 * down. With no key set in hand, a failed fetch caches nothing, and the next
 * caller tries again.
 *
 * A discovery document whose `issuer` is not the configured one is refused, and
 * no key is fetched from it (OpenID Connect Discovery 1.0, section 4.3). Each
 * Provider has its own realm, so each issuer has its own key set: a document of
 * another realm must never fill this one's.
 *
 * PHP-FPM starts each request with empty memory. Give a PSR-16 `$cache`, such as
 * APCu or Redis, so that the processes share one key set and one fetch a minute.
 * Without it, each request fetches the key set again. The cache holds the public
 * keys and the time of the last fetch, and nothing secret.
 */
final class SigningKeys
{
    /** The one algorithm the SDK accepts, in the key set and on the token. */
    public const ALGORITHM = 'RS256';
    /**
     * How long the cache refuses a second fetch after one completed. Shorter than
     * any token lifetime, so a rotation is never waited out.
     */
    public const REFRESH_INTERVAL_SECONDS = 60.0;
    public const FETCH_TIMEOUT_SECONDS = 5.0;
    /** An RSA key under this many bits is skipped: it verifies nothing. */
    public const MIN_MODULUS_BITS = 2048;

    private readonly string $issuer;
    private readonly Transport $http;
    private readonly \Closure $clock;
    private readonly string $cacheKey;
    /** @var array<array-key, array{n: string, e: string}> */
    private array $members = [];
    /** @var array<array-key, \OpenSSLAsymmetricKey> */
    private array $keys = [];
    private ?string $jwksUri = null;
    private ?float $fetchedAt = null;
    private bool $refreshFailed = false;

    /**
     * @param string $issuer the `issuer` member of your org in keelie: your own realm
     * @param Transport|null $http the client the keys are fetched with
     * @param CacheInterface|null $cache shares the key set between processes
     * @param (\Closure(): float)|null $clock seconds since the epoch
     */
    public function __construct(
        string $issuer,
        ?Transport $http = null,
        private readonly ?CacheInterface $cache = null,
        ?\Closure $clock = null,
        private readonly float $refreshIntervalSeconds = self::REFRESH_INTERVAL_SECONDS,
    ) {
        $this->issuer = rtrim($issuer, '/');
        $this->http = $http ?? new CurlTransport(self::FETCH_TIMEOUT_SECONDS);
        $this->clock = $clock ?? static fn (): float => microtime(true);
        $this->cacheKey = 'keelie.keys.' . substr(hash('sha256', $this->issuer), 0, 32);
    }

    /**
     * The key with this id, fetching the set once if it is not there.
     *
     * @throws UnknownKey
     * @throws KeysUnavailable
     */
    public function key(string $kid): \OpenSSLAsymmetricKey
    {
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        $this->adoptCache();
        if (!isset($this->keys[$kid]) && $this->mayFetch()) {
            $this->refresh();
        }

        return $this->keys[$kid] ?? throw new UnknownKey('unknown kid');
    }

    /** Offline with no key, Degraded if the last fetch failed, else Connected. It makes no network call. */
    public function status(): Status
    {
        $this->adoptCache();
        if ($this->keys === []) {
            return Status::Offline;
        }

        return $this->refreshFailed ? Status::Degraded : Status::Connected;
    }

    private function now(): float
    {
        return (float) ($this->clock)();
    }

    private function mayFetch(): bool
    {
        return $this->fetchedAt === null || $this->now() - $this->fetchedAt >= $this->refreshIntervalSeconds;
    }

    private function refresh(): void
    {
        try {
            [$jwksUri, $keySet] = $this->fetch();
            $members = $this->signingKeys($keySet);
        } catch (\Throwable $error) {
            if ($this->fetchedAt === null) {
                // Cold: nothing to verify with. Nothing is cached, so the next caller tries again.
                Log::warning('apiable.keys_unavailable: ' . Log::errorName($error));
                throw new KeysUnavailable(Log::errorName($error), 0, $error);
            }
            // Warm: the keys in hand go on verifying, and the issuer is not asked
            // again for another interval.
            $this->fetchedAt = $this->now();
            $this->refreshFailed = true;
            Log::warning('apiable.keys_not_refreshed: ' . Log::errorName($error));
            $this->writeCache();

            return;
        }
        $this->jwksUri = $jwksUri;
        $this->load($members);
        $this->fetchedAt = $this->now();
        $this->refreshFailed = false;
        $kids = array_map('strval', array_keys($this->keys));
        sort($kids, SORT_STRING);
        Log::info('apiable.keys_loaded kids=' . json_encode($kids, JSON_UNESCAPED_SLASHES));
        $this->writeCache();
    }

    /** @return array{string, mixed} the `jwks_uri` and the `keys` member of the key set */
    private function fetch(): array
    {
        $jwksUri = $this->jwksUri;
        if ($jwksUri === null) {
            $document = $this->getJson($this->issuer . '/.well-known/openid-configuration');
            $issuer = self::member($document, 'issuer');
            if (!is_string($issuer) || rtrim($issuer, '/') !== $this->issuer) {
                throw new KeySetError('issuer');
            }
            $jwksUri = self::member($document, 'jwks_uri');
            if (!is_string($jwksUri)) {
                throw new KeySetError('jwks_uri');
            }
        }

        return [$jwksUri, self::member($this->getJson($jwksUri), 'keys')];
    }

    private function getJson(string $url): mixed
    {
        $response = $this->http->send('GET', $url, ['Accept' => 'application/json']);
        if (!$response->ok()) {
            throw new KeySetError("status {$response->status}");
        }

        return Json::lenient($response->body);
    }

    private static function member(mixed $document, string $name): mixed
    {
        if (!$document instanceof JsonObject) {
            throw new KeySetError('document');
        }
        if (!$document->has($name)) {
            throw new KeySetError($name);
        }

        return $document->get($name);
    }

    /** @return array<array-key, array{n: string, e: string}> */
    private function signingKeys(mixed $keySet): array
    {
        if (!is_array($keySet)) {
            throw new KeySetError('keys');
        }
        $members = [];
        foreach ($keySet as $jwk) {
            // The issuer can publish an encryption key beside the signing key. Only an
            // RSA key for signing, with the one algorithm and a kid, verifies a token.
            if (!$jwk instanceof JsonObject) {
                continue;
            }
            $kid = $jwk->get('kid');
            if (
                !is_string($kid)
                || $jwk->get('kty') !== 'RSA'
                || !in_array($jwk->get('use'), [null, 'sig'], true)
                || !in_array($jwk->get('alg'), [null, self::ALGORITHM], true)
            ) {
                continue;
            }
            $n = $jwk->get('n');
            $e = $jwk->get('e');
            // The public members only: a private member published by mistake is never loaded.
            if (is_string($n) && is_string($e) && self::publicKey($n, $e) !== null) {
                $members[$kid] = ['n' => $n, 'e' => $e];
            } else {
                // A key the SDK cannot load is skipped. The rest of the set loads.
                Log::warning('apiable.key_skipped kid=' . json_encode($kid, JSON_UNESCAPED_SLASHES));
            }
        }

        return $members;
    }

    /** @param array<array-key, array{n: string, e: string}> $members */
    private function load(array $members): void
    {
        $keys = [];
        foreach ($members as $kid => $member) {
            $key = self::publicKey($member['n'], $member['e']);
            if ($key !== null) {
                $keys[$kid] = $key;
            }
        }
        $this->members = $members;
        $this->keys = $keys;
    }

    /** The RSA public key, or null if it is not one the SDK verifies with. */
    private static function publicKey(string $n, string $e): ?\OpenSSLAsymmetricKey
    {
        $modulus = ltrim(Base64Url::decodeMember($n), "\0");
        $exponent = ltrim(Base64Url::decodeMember($e), "\0");
        if ($modulus === '' || $exponent === '') {
            return null;
        }
        $bits = strlen($modulus) * 8 - (8 - strlen(decbin(ord($modulus[0]))));
        if ($bits < self::MIN_MODULUS_BITS || (ord($modulus[-1]) & 1) === 0) {
            return null;
        }
        $exponentTooLarge = strlen($exponent) > strlen($modulus)
            || (strlen($exponent) === strlen($modulus) && strcmp($exponent, $modulus) >= 0);
        if ((strlen($exponent) === 1 && ord($exponent) < 3) || (ord($exponent[-1]) & 1) === 0 || $exponentTooLarge) {
            return null;
        }
        $rsa = self::der("\x30", self::derInteger($modulus) . self::derInteger($exponent));
        $algorithm = self::der("\x30", "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
        $spki = self::der("\x30", $algorithm . self::der("\x03", "\x00" . $rsa));
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        while (openssl_error_string() !== false) {
            // Clear OpenSSL's error queue: an old error must not show up in a later call.
        }

        return $key === false ? null : $key;
    }

    private static function derInteger(string $bytes): string
    {
        return self::der("\x02", (ord($bytes[0]) & 0x80) !== 0 ? "\0" . $bytes : $bytes);
    }

    private static function der(string $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            return $tag . chr($length) . $content;
        }
        $octets = ltrim(pack('N', $length), "\0");

        return $tag . chr(0x80 | strlen($octets)) . $octets . $content;
    }

    /** Take the key set another process fetched, if it is newer than the one in hand. */
    private function adoptCache(): void
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
            !is_array($state)
            || !(is_float($state['fetched_at'] ?? null) || is_int($state['fetched_at'] ?? null))
            || !is_array($state['keys'] ?? null)
            || !is_string($state['jwks_uri'] ?? null)
            || ($this->fetchedAt !== null && $state['fetched_at'] <= $this->fetchedAt)
        ) {
            return;
        }
        $members = [];
        foreach ($state['keys'] as $kid => $member) {
            if (is_array($member) && is_string($member['n'] ?? null) && is_string($member['e'] ?? null)) {
                $members[$kid] = ['n' => $member['n'], 'e' => $member['e']];
            }
        }
        $this->load($members);
        $this->jwksUri = $state['jwks_uri'];
        $this->fetchedAt = (float) $state['fetched_at'];
        $this->refreshFailed = ($state['failed'] ?? false) === true;
    }

    private function writeCache(): void
    {
        if ($this->cache === null || $this->jwksUri === null) {
            return;
        }
        try {
            $this->cache->set($this->cacheKey, [
                'jwks_uri' => $this->jwksUri,
                'keys' => $this->members,
                'fetched_at' => $this->fetchedAt,
                'failed' => $this->refreshFailed,
            ]);
        } catch (\Throwable $error) {
            Log::warning('apiable.cache_failed error=' . Log::errorName($error));
        }
    }
}
