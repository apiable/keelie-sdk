<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\Http\Response;
use Keelie\Http\Transport;
use Keelie\Http\TransportError;
use Keelie\Internal\Base64Url;
use Keelie\KeelieClient;
use Keelie\Log;
use Keelie\SigningKeys;
use Keelie\TokenVerifier;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\AbstractLogger;
use Psr\SimpleCache\CacheInterface;

/** Values and fakes the tests share. No test reaches the network. */
final class Support
{
    public const ISSUER = 'https://portal-labs.keelie.io/realms/6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12';
    public const RESOURCE = 'https://api.example.com/v1';
    public const ORG_ID = '6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12';
    public const CONSUMER_ID = '0b9a7c55-2f5e-4d4c-8d2a-6f1b3c9e7a21';

    /** @var array<string, KeyPair> */
    private static array $pairs = [];

    public static function pair(string $kid = 'k1'): KeyPair
    {
        return self::$pairs[$kid] ??= KeyPair::generate($kid);
    }

    /** @param array<string, mixed> $overrides */
    public static function claims(array $overrides = []): array
    {
        $now = time();

        return array_merge([
            'iss' => self::ISSUER,
            'aud' => self::RESOURCE,
            'azp' => 'consumer-client',
            'org_id' => self::ORG_ID,
            'scope' => 'orders:read profile',
            'typ' => 'Bearer',
            'jti' => 'token-1',
            'sub' => 'service-account-user',
            'iat' => $now,
            'exp' => $now + 300,
        ], $overrides);
    }

    /** @param array<string, mixed> $overrides */
    public static function token(array $overrides = [], ?KeyPair $pair = null): string
    {
        return ($pair ?? self::pair())->sign(self::claims($overrides));
    }

    public static function verifier(?FakeIssuer $issuer = null): TokenVerifier
    {
        $issuer ??= new FakeIssuer([self::pair()]);

        return new TokenVerifier(self::ISSUER, self::RESOURCE, self::ORG_ID, new SigningKeys(self::ISSUER, $issuer));
    }

    public static function factory(): Psr17Factory
    {
        return new Psr17Factory();
    }

    public static function request(string $method, string $uri, ?string $token = null, string $body = ''): ServerRequestInterface
    {
        $request = self::factory()->createServerRequest($method, $uri);
        if ($token !== null) {
            $request = $request->withHeader('Authorization', "Bearer {$token}");
        }

        return $body === '' ? $request : $request->withBody(self::factory()->createStream($body));
    }

    public static function logs(): Logs
    {
        $logs = new Logs();
        Log::setLogger($logs);

        return $logs;
    }
}

/** An RSA key pair, for signing test tokens. */
final class KeyPair
{
    private function __construct(
        public readonly string $kid,
        private readonly \OpenSSLAsymmetricKey $private,
        /** @var array<string, string> */
        public readonly array $jwk,
    ) {
    }

    public static function generate(string $kid, int $bits = 2048): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed');
        }
        $details = openssl_pkey_get_details($key);

        return new self($kid, $key, [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => Base64Url::encode($details['rsa']['n']),
            'e' => Base64Url::encode($details['rsa']['e']),
        ]);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public function sign(array $claims, array $header = []): string
    {
        $header = array_merge(['alg' => 'RS256', 'kid' => $this->kid, 'typ' => 'JWT'], $header);
        $input = Base64Url::encode(json_encode($header, JSON_UNESCAPED_SLASHES))
            . '.' . Base64Url::encode(json_encode($claims, JSON_UNESCAPED_SLASHES));
        openssl_sign($input, $signature, $this->private, OPENSSL_ALGO_SHA256);

        return $input . '.' . Base64Url::encode($signature);
    }
}

/** The issuer: its discovery document and its key set. */
final class FakeIssuer implements Transport
{
    /** @var list<string> */
    public array $requests = [];
    public bool $down = false;
    public ?string $documentIssuer = null;

    /**
     * @param list<KeyPair> $pairs
     * @param list<array<string, mixed>> $extraKeys
     */
    public function __construct(public array $pairs, public array $extraKeys = [], public string $issuer = Support::ISSUER)
    {
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $this->requests[] = $url;
        if ($this->down) {
            throw new TransportError('connection refused');
        }
        if ($url === "{$this->issuer}/.well-known/openid-configuration") {
            return new Response(200, [], (string) json_encode([
                'issuer' => $this->documentIssuer ?? $this->issuer,
                'jwks_uri' => "{$this->issuer}/protocol/openid-connect/certs",
            ], JSON_UNESCAPED_SLASHES));
        }
        if ($url === "{$this->issuer}/protocol/openid-connect/certs") {
            $keys = array_merge(array_map(static fn (KeyPair $pair): array => $pair->jwk, $this->pairs), $this->extraKeys);

            return new Response(200, [], (string) json_encode(['keys' => $keys]));
        }

        return new Response(404);
    }

    public function count(): int
    {
        return count($this->requests);
    }
}

/** keelie: answers each request from a queue, and keeps what it was sent. */
final class FakeKeelie implements KeelieClient
{
    /** @var list<array{method: string, path: string, body: ?string, headers: array<string, string>}> */
    public array $requests = [];

    /** @param list<Response|\Throwable> $answers the default is 202 */
    public function __construct(public array $answers = [])
    {
    }

    public function request(string $method, string $path, ?string $body = null, array $headers = []): Response
    {
        $this->requests[] = ['method' => $method, 'path' => $path, 'body' => $body, 'headers' => $headers];
        $answer = array_shift($this->answers) ?? new Response(202);
        if ($answer instanceof \Throwable) {
            throw $answer;
        }

        return $answer;
    }

    /** @return list<array<string, string>> the events of the request at `$index` */
    public function events(int $index): array
    {
        return json_decode((string) $this->requests[$index]['body'], true)['events'];
    }
}

/** A PSR-16 cache in memory, to share state between two SDK objects as two processes would. */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $values = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->values) ? unserialize(serialize($this->values[$key])) : $default;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->values[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->values = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }
}

/** The app behind a middleware: it answers 200, or the status it is given, and keeps the request it got. */
final class App implements RequestHandlerInterface
{
    public ?ServerRequestInterface $request = null;

    public function __construct(private readonly int $status = 200)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->request = $request;
        $response = Support::factory()->createResponse($this->status);
        $response->getBody()->write('app:' . (string) $request->getBody());

        return $response;
    }
}

/** The SDK's log lines. */
final class Logs extends AbstractLogger
{
    /** @var list<string> */
    public array $lines = [];

    public function log($level, string|\Stringable $message, array $context = []): void
    {
        $this->lines[] = "{$level} {$message}";
    }

    public function text(): string
    {
        return implode("\n", $this->lines);
    }
}

/** A clock a test moves by hand. */
final class Clock
{
    public function __construct(public float $now = 1800000000.0)
    {
    }

    public function closure(): \Closure
    {
        return fn (): float => $this->now;
    }
}
