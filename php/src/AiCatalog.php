<?php

declare(strict_types=1);

namespace Keelie;

use Psr\SimpleCache\CacheInterface;

/**
 * Your AI Catalog, fetched from keelie and kept for 60 seconds.
 *
 * The catalog is served at `/.well-known/ard.json`, where ARD v0.91 looks for it,
 * and at `/.well-known/ai-catalog.json`, where the ai-catalog specification looks
 * and an MCP proposal points. Both paths serve the same body, from the same copy.
 *
 * keelie builds the catalog from your published plans. A plan you publish shows
 * here within 60 seconds, and within up to 120 seconds at a client that caches
 * the answer.
 *
 * The SDK does not change the document. It keeps no copy past 60 seconds: if
 * keelie does not answer when the copy is old, the answer is 503, not an old
 * catalog. After a failure, it asks keelie again after 10 seconds, not on each
 * request.
 *
 * Under PHP-FPM, give a PSR-16 `$cache`, so that the processes share one copy.
 * Without it, each request for the catalog fetches it from keelie.
 *
 * Serve it with the middleware {@see Middleware\AiCatalogMiddleware}, or call
 * {@see answer()} from any other server.
 */
final class AiCatalog
{
    /** The one place that names keelie's catalog endpoint. */
    public const KEELIE_PATH = '/ai-catalog';
    public const ARD_PATH = '/.well-known/ard.json';
    public const CATALOG_PATH = '/.well-known/ai-catalog.json';
    /**
     * Where an agent looks for the AI Catalog of a domain, and the media type of
     * each path. ARD v0.91 reads `ard.json` and names no media type for it. The
     * ai-catalog specification reads `ai-catalog.json`. A GET or a HEAD of either
     * needs no token, but only once an AiCatalog serves it. This map is the one
     * list of those paths: the guards and the catalog both read it.
     */
    public const MEDIA_TYPES = [
        self::ARD_PATH => 'application/json',
        self::CATALOG_PATH => 'application/ai-catalog+json',
    ];
    public const CACHE_SECONDS = 60.0;
    public const RETRY_SECONDS = 10.0;

    private readonly \Closure $clock;
    private readonly string $cacheKey;
    private ?string $body = null;
    private float $fetchedAt = 0.0;
    private ?float $failedAt = null;

    /**
     * @param KeelieClient $keelie sends a request to keelie with the auth of a
     *                             credential that may read products: an SdkCredential
     * @param ProtectedResourceMetadata $metadata the one your token guard uses. Making
     *                                            the catalog with it tells the token guards
     *                                            to let a GET or a HEAD of the two catalog
     *                                            paths pass with no token.
     * @param (\Closure(): float)|null $clock seconds since the epoch
     */
    public function __construct(
        private readonly KeelieClient $keelie,
        ProtectedResourceMetadata $metadata,
        private readonly ?CacheInterface $cache = null,
        ?\Closure $clock = null,
    ) {
        $metadata->aiCatalog = true;
        $this->clock = $clock ?? static fn (): float => microtime(true);
        // Every copy of the catalog for one resource is the same: the processes share it.
        $this->cacheKey = 'keelie.catalog.' . substr(hash('sha256', $metadata->resource), 0, 32);
    }

    /** The answer for `$path`, or null if `$path` is not a catalog path. */
    public function answer(string $path): ?CatalogAnswer
    {
        $mediaType = self::MEDIA_TYPES[$path] ?? null;
        if ($mediaType === null) {
            return null;
        }
        $body = $this->catalog();
        if ($body === null) {
            return new CatalogAnswer(503, ['Retry-After' => '10', 'Cache-Control' => 'no-store'], '');
        }

        return new CatalogAnswer(200, ['Content-Type' => $mediaType, 'Cache-Control' => 'max-age=60'], $body);
    }

    private function now(): float
    {
        return (float) ($this->clock)();
    }

    /** The catalog, fetched again when the copy is 60 seconds old. Null if keelie fails. */
    private function catalog(): ?string
    {
        if (!$this->settled()) {
            $this->adoptCache();
        }
        if ($this->settled()) {
            return $this->failedAt === null ? $this->body : null;
        }
        $this->body = null;
        try {
            $response = $this->keelie->request('GET', self::KEELIE_PATH);
        } catch (\Throwable $error) {
            Log::warning('apiable.catalog_fetch_failed error=' . Log::errorName($error));

            return $this->failed();
        }
        if ($response->status !== 200) {
            Log::warning("apiable.catalog_fetch_failed status={$response->status}");

            return $this->failed();
        }
        $this->body = $response->body;
        $this->fetchedAt = $this->now();
        $this->failedAt = null;
        $this->writeCache();

        return $this->body;
    }

    private function failed(): null
    {
        $this->failedAt = $this->now();
        $this->writeCache();

        return null;
    }

    /** True while the copy is fresh, or while a failure is recent: no fetch is due. */
    private function settled(): bool
    {
        $now = $this->now();
        if ($this->failedAt !== null) {
            return $now - $this->failedAt < self::RETRY_SECONDS;
        }

        return $this->body !== null && $now - $this->fetchedAt < self::CACHE_SECONDS;
    }

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
        if (!is_array($state) || !is_float($state['at'] ?? null)) {
            return;
        }
        if (is_string($state['body'] ?? null)) {
            $this->body = $state['body'];
            $this->fetchedAt = $state['at'];
            $this->failedAt = null;
        } else {
            $this->body = null;
            $this->failedAt = $state['at'];
        }
    }

    private function writeCache(): void
    {
        if ($this->cache === null) {
            return;
        }
        $failed = $this->failedAt !== null;
        try {
            $this->cache->set(
                $this->cacheKey,
                ['body' => $failed ? null : $this->body, 'at' => $failed ? $this->failedAt : $this->fetchedAt],
                (int) ($failed ? self::RETRY_SECONDS : self::CACHE_SECONDS),
            );
        } catch (\Throwable $error) {
            Log::warning('apiable.cache_failed error=' . Log::errorName($error));
        }
    }
}
