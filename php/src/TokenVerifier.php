<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Internal\Base64Url;
use Keelie\Internal\Json;
use Keelie\Internal\JsonError;
use Keelie\Internal\JsonObject;
use Keelie\Internal\PyText;
use Keelie\Internal\Uuid;

/**
 * Verifies the tokens of one issuer, for one audience and one org, inside your
 * own process.
 *
 * The SDK never asks Apiable whether a token is good. It checks the signature
 * against the issuer's key set (see {@see SigningKeys}) and the claims against
 * what you configured. The checks run in this order, and the first that fails
 * refuses the token:
 *
 * 1. The token parses, its `alg` is `RS256` and it names a `kid`. A token that
 *    says `none` or `HS256` is refused before any key is fetched.
 * 2. The key with that `kid` is in the issuer's key set.
 * 3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
 * 4. `azp` names the client, and `org_id` is your own org id.
 * 5. `typ` is `Bearer`. An ID token is signed with the same key.
 *
 * The issuer is your own realm: the `issuer` member of your org in keelie. Each
 * Provider has its own realm, with its own `iss` and its own key set, so a token
 * of another Provider fails at step 2 or 3. The `org_id` check stays as a second
 * line: a Provider whose Consumers keelie made before it had a realm shares one
 * issuer and one key set with others, and there `org_id` tells them apart.
 *
 * Every refusal throws {@see TokenRejected}. Its reason is for your log, not for
 * the caller: a caller must not learn "expired" from "wrong key".
 *
 * The reasons are the Python SDK's, for the same token. The Python SDK reads the
 * token with PyJWT, so this class reads it by PyJWT's rules, in PyJWT's order.
 */
final class TokenVerifier
{
    public const TOKEN_TYPE = 'Bearer';
    /** Clock skew a token is forgiven. */
    public const LEEWAY_SECONDS = 30;
    /** The latest `exp` Python can turn into a date: the end of the year 9999. */
    private const MAX_TIMESTAMP = 253402300799;
    /** The extensions PyJWT understands in `crit`. */
    private const CRITICAL = ['b64'];

    private readonly string $orgId;
    private readonly SigningKeys $keys;
    private readonly \Closure $clock;

    /**
     * @param string $issuer the `issuer` member of your org in keelie: your own realm
     * @param string $audience your API's `resource` in keelie, exactly
     * @param string $orgId your org id. A value that is not a UUID throws InvalidArgumentException.
     * @param SigningKeys|null $keys the key set. One made from `$issuer` unless you give another.
     * @param (\Closure(): float)|null $clock seconds since the epoch
     */
    public function __construct(
        private readonly string $issuer,
        public readonly string $audience,
        string $orgId,
        ?SigningKeys $keys = null,
        private readonly int $leewaySeconds = self::LEEWAY_SECONDS,
        ?\Closure $clock = null,
    ) {
        $this->orgId = Uuid::parse($orgId)
            ?? throw new \InvalidArgumentException('orgId is not a UUID: ' . json_encode($orgId));
        $this->keys = $keys ?? new SigningKeys($issuer);
        $this->clock = $clock ?? static fn (): float => microtime(true);
    }

    /**
     * The claims of the token.
     *
     * @throws TokenRejected with the reason, for every token that does not verify
     */
    public function verify(string $token): Claims
    {
        try {
            return $this->check($token);
        } catch (TokenRejected $rejected) {
            Log::info("apiable.token_rejected reason={$rejected->reason}");
            throw $rejected;
        }
    }

    /**
     * What the SDK knows of the issuer, from its last fetch of the key set.
     *
     * It makes no network call, and the SDK does not poll. The SDK fetches only on
     * a cold start and for a key it does not know. So while the keys in hand verify
     * every token, an outage of the issuer leaves the status as it is.
     */
    public function status(): Status
    {
        return $this->keys->status();
    }

    private static function reject(string $reason, ?\Throwable $previous = null): never
    {
        throw new TokenRejected($reason, $previous);
    }

    private function check(string $token): Claims
    {
        [$header, $payloadBytes, $signingInput, $signature] = $this->load($token);
        if ($header->get('alg') !== SigningKeys::ALGORITHM) {
            self::reject('algorithm');
        }
        $kid = $header->get('kid');
        if (!is_string($kid) || $kid === '') {
            self::reject('kid');
        }
        try {
            $key = $this->keys->key($kid);
        } catch (UnknownKey $error) {
            self::reject('kid', $error);
        } catch (KeysUnavailable $error) {
            self::reject('keys_unavailable', $error);
        }

        // A detached payload (RFC 7797) is never what keelie signs.
        if ($header->has('b64') && $header->get('b64') === false) {
            self::reject('malformed');
        }
        $verified = openssl_verify($signingInput, $signature, $key, OPENSSL_ALGO_SHA256);
        while (openssl_error_string() !== false) {
            // Clear OpenSSL's error queue: an old error must not show up in a later call.
        }
        if ($verified !== 1) {
            self::reject('signature');
        }
        try {
            $payload = Json::lenient($payloadBytes);
        } catch (JsonError $error) {
            self::reject('malformed', $error);
        }
        if (!$payload instanceof JsonObject) {
            self::reject('malformed');
        }

        $this->checkTimes($payload);
        $this->checkIssuerAndAudience($payload);

        return $this->claims($payload);
    }

    /**
     * The header, the payload's bytes, the signing input and the signature, as
     * PyJWT's `_load` and `_validate_headers` read them.
     *
     * @return array{JsonObject, string, string, string}
     */
    private function load(string $token): array
    {
        $first = strpos($token, '.');
        $last = strrpos($token, '.');
        if ($first === false || $last === false || $first === $last) {
            self::reject('malformed');
        }
        $signingInput = substr($token, 0, $last);
        $headerBytes = Base64Url::decode(substr($token, 0, $first));
        $payloadSegment = substr($token, $first + 1, $last - $first - 1);
        $signature = Base64Url::decode(substr($token, $last + 1));
        if ($headerBytes === null || $signature === null) {
            self::reject('malformed');
        }
        try {
            $header = Json::lenient($headerBytes);
        } catch (JsonError $error) {
            self::reject('malformed', $error);
        }
        if (!$header instanceof JsonObject) {
            self::reject('malformed');
        }
        if ($header->has('b64') && $header->get('b64') === false) {
            if ($payloadSegment !== '') {
                self::reject('malformed');
            }
            $payload = '';
        } else {
            $payload = Base64Url::decode($payloadSegment) ?? self::reject('malformed');
        }
        if ($header->has('kid') && !is_string($header->get('kid'))) {
            self::reject('malformed');
        }
        if ($header->has('crit')) {
            $this->checkCritical($header);
        }

        return [$header, $payload, $signingInput, $signature];
    }

    private function checkCritical(JsonObject $header): void
    {
        $crit = $header->get('crit');
        if (!is_array($crit) || $crit === []) {
            self::reject('malformed');
        }
        foreach ($crit as $extension) {
            if (!is_string($extension) || !in_array($extension, self::CRITICAL, true) || !$header->has($extension)) {
                self::reject('malformed');
            }
        }
    }

    /** `exp` is required. Then `iat`, `nbf` and `exp`, each when present, in PyJWT's order. */
    private function checkTimes(JsonObject $payload): void
    {
        if ($payload->get('exp') === null) {
            self::reject('claims');
        }
        $now = (float) ($this->clock)();
        if ($payload->has('iat')) {
            $iat = self::pyInt($payload->get('iat'));
            if ($iat === null || $iat > $now + $this->leewaySeconds) {
                self::reject('not_yet_valid');
            }
        }
        if ($payload->has('nbf')) {
            $nbf = self::pyInt($payload->get('nbf')) ?? self::reject('malformed');
            if ($nbf > $now + $this->leewaySeconds) {
                self::reject('not_yet_valid');
            }
        }
        $exp = self::pyInt($payload->get('exp')) ?? self::reject('malformed');
        if ($exp <= $now - $this->leewaySeconds) {
            self::reject('expired');
        }
    }

    private function checkIssuerAndAudience(JsonObject $payload): void
    {
        if (!$payload->has('iss')) {
            self::reject('claims');
        }
        if ($payload->get('iss') !== $this->issuer) {
            self::reject('issuer');
        }
        $aud = $payload->get('aud');
        if (!self::pyTruthy($aud)) {
            self::reject('audience');
        }
        if (is_string($aud)) {
            $aud = [$aud];
        }
        if (!is_array($aud) || !in_array($this->audience, $aud, true)) {
            self::reject('audience');
        }
        foreach ($aud as $member) {
            if (!is_string($member)) {
                self::reject('audience');
            }
        }
        // PyJWT refuses a `sub` or a `jti` that is not a string.
        if ($payload->has('sub') && !is_string($payload->get('sub'))) {
            self::reject('malformed');
        }
        if ($payload->has('jti') && !is_string($payload->get('jti'))) {
            self::reject('malformed');
        }
    }

    private function claims(JsonObject $payload): Claims
    {
        $azp = $payload->get('azp');
        $scope = $payload->has('scope') ? $payload->get('scope') : '';
        $jti = $payload->get('jti');
        $orgId = Uuid::parse($payload->get('org_id')) ?? self::reject('claims');
        if (!is_string($azp) || $azp === '' || !is_string($scope)) {
            self::reject('claims');
        }
        if ($orgId !== $this->orgId) {
            self::reject('org');
        }
        if ($payload->get('typ') !== self::TOKEN_TYPE) {
            self::reject('typ');
        }
        $exp = $payload->get('exp');
        if (!(is_int($exp) || is_float($exp)) || $exp > self::MAX_TIMESTAMP) {
            self::reject('claims');
        }
        $consumer = $payload->get('consumer_id');
        $consumerId = null;
        if ($consumer !== null) {
            $consumerId = Uuid::parse($consumer) ?? self::reject('claims');
        }
        $expiresAt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $exp), new \DateTimeZone('UTC'));
        if ($expiresAt === false) {
            self::reject('claims');
        }

        return new Claims(
            azp: $azp,
            orgId: $orgId,
            scopes: array_values(array_unique(PyText::split($scope))),
            jti: is_string($jti) ? $jti : null,
            expiresAt: $expiresAt->setTimezone(new \DateTimeZone('UTC')),
            consumerId: $consumerId,
        );
    }

    /** The value as Python's `int()` reads it, or null where `int()` fails. */
    private static function pyInt(mixed $value): int|float|null
    {
        return match (true) {
            $value === true => 1,
            $value === false => 0,
            is_int($value) => $value,
            is_float($value) => is_finite($value) ? ($value < 0 ? ceil($value) : floor($value)) : null,
            is_string($value) => self::pyIntString($value),
            default => null,
        };
    }

    private static function pyIntString(string $value): int|float|null
    {
        if (preg_match('/^\s*[+-]?\d+(?:_\d+)*\s*$/D', $value) !== 1) {
            return null;
        }
        $digits = str_replace('_', '', trim($value));
        $int = filter_var($digits, FILTER_VALIDATE_INT);

        return $int === false ? (float) $digits : $int;
    }

    /** Python's truth: null, false, zero and an empty string, list or object are false. */
    private static function pyTruthy(mixed $value): bool
    {
        return !($value === null || $value === false || $value === 0 || $value === 0.0 || $value === ''
            || $value === [] || ($value instanceof JsonObject && $value->members === []));
    }
}
