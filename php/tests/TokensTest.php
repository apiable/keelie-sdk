<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\Internal\Base64Url;
use Keelie\Log;
use Keelie\SigningKeys;
use Keelie\Status;
use Keelie\TokenRejected;
use Keelie\TokenVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TokensTest extends TestCase
{
    protected function setUp(): void
    {
        Support::logs();
    }

    protected function tearDown(): void
    {
        Log::setLogger(null);
    }

    private static function reason(TokenVerifier $verifier, string $token): ?string
    {
        try {
            $verifier->verify($token);

            return null;
        } catch (TokenRejected $rejected) {
            return $rejected->reason;
        }
    }

    public function testAGoodTokenGivesItsClaims(): void
    {
        $claims = Support::verifier()->verify(Support::token(['consumer_id' => strtoupper(Support::CONSUMER_ID)]));

        self::assertSame('consumer-client', $claims->azp);
        self::assertSame(Support::ORG_ID, $claims->orgId);
        self::assertSame(['orders:read', 'profile'], $claims->scopes);
        self::assertTrue($claims->hasScope('orders:read'));
        self::assertFalse($claims->hasScope('orders'));
        self::assertSame('token-1', $claims->jti);
        self::assertSame(Support::CONSUMER_ID, $claims->consumerId);
        self::assertSame('UTC', $claims->expiresAt->getTimezone()->getName());
    }

    public function testACredentialsTokenHasNoConsumer(): void
    {
        self::assertNull(Support::verifier()->verify(Support::token())->consumerId);
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function refusals(): iterable
    {
        yield 'expired' => [['exp' => time() - 120], 'expired'];
        yield 'not yet valid' => [['nbf' => time() + 600], 'not_yet_valid'];
        yield 'another issuer' => [['iss' => 'https://other.keelie.io/realms/x'], 'issuer'];
        yield 'another audience' => [['aud' => 'https://api.example.com/v2'], 'audience'];
        yield 'another org' => [['org_id' => 'c1b6f3a2-8d4e-4f5a-9b6c-7d8e9f0a1b2c'], 'org'];
        yield 'an ID token' => [['typ' => 'ID'], 'typ'];
        yield 'no azp' => [['azp' => ''], 'claims'];
        yield 'a consumer that is not a UUID' => [['consumer_id' => 'nobody'], 'claims'];
    }

    /** @param array<string, mixed> $claims */
    #[DataProvider('refusals')]
    public function testARefusedTokenGivesTheReasonForTheLog(array $claims, string $reason): void
    {
        $logs = Support::logs();

        self::assertSame($reason, self::reason(Support::verifier(), Support::token($claims)));
        self::assertStringContainsString("apiable.token_rejected reason={$reason}", $logs->text());
    }

    public function testAnAlgorithmOtherThanRs256IsRefusedBeforeAnyKeyIsFetched(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $verifier = Support::verifier($issuer);
        $payload = Base64Url::encode((string) json_encode(Support::claims()));
        foreach (['none', 'HS256', 'RS512'] as $alg) {
            $header = Base64Url::encode((string) json_encode(['alg' => $alg, 'kid' => 'k1']));
            self::assertSame('algorithm', self::reason($verifier, "{$header}.{$payload}.c2ln"));
        }
        self::assertSame(0, $issuer->count());
    }

    public function testAKeyOfAnotherPairFailsTheSignature(): void
    {
        $other = KeyPair::generate('k1');

        self::assertSame('signature', self::reason(Support::verifier(), Support::token([], $other)));
    }

    public function testAnUnknownKidFetchesOnceAMinuteThenIsRefused(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $clock = new Clock();
        $verifier = new TokenVerifier(
            Support::ISSUER,
            Support::RESOURCE,
            Support::ORG_ID,
            new SigningKeys(Support::ISSUER, $issuer, clock: $clock->closure()),
        );
        $stranger = KeyPair::generate('k9');

        $verifier->verify(Support::token());
        self::assertSame(2, $issuer->count()); // discovery, then the key set
        $clock->now += 61;
        for ($i = 0; $i < 5; $i++) {
            self::assertSame('kid', self::reason($verifier, Support::token([], $stranger)));
        }
        // One fetch of the key set, not five. The jwks_uri is kept.
        self::assertSame(3, $issuer->count());
    }

    public function testARotatedKeyIsPickedUpWithoutARestart(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $clock = new Clock();
        $verifier = new TokenVerifier(
            Support::ISSUER,
            Support::RESOURCE,
            Support::ORG_ID,
            new SigningKeys(Support::ISSUER, $issuer, clock: $clock->closure()),
        );
        $verifier->verify(Support::token());
        $next = Support::pair('k2');
        $issuer->pairs[] = $next;
        $clock->now += 60;

        self::assertSame('consumer-client', $verifier->verify(Support::token([], $next))->azp);
    }

    public function testTheStatusFollowsTheLastFetch(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $clock = new Clock();
        $verifier = new TokenVerifier(
            Support::ISSUER,
            Support::RESOURCE,
            Support::ORG_ID,
            new SigningKeys(Support::ISSUER, $issuer, clock: $clock->closure()),
        );
        self::assertSame(Status::Offline, $verifier->status());

        $verifier->verify(Support::token());
        self::assertSame(Status::Connected, $verifier->status());

        $issuer->down = true;
        $clock->now += 61;
        self::assertSame('kid', self::reason($verifier, Support::token([], Support::pair('k3'))));
        self::assertSame(Status::Degraded, $verifier->status());
        // The keys in hand go on verifying.
        self::assertSame('consumer-client', $verifier->verify(Support::token())->azp);
    }

    public function testAColdFailureCachesNothingAndTheNextCallerTriesAgain(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $issuer->down = true;
        $verifier = Support::verifier($issuer);
        $logs = Support::logs();

        self::assertSame('keys_unavailable', self::reason($verifier, Support::token()));
        self::assertStringContainsString('apiable.keys_unavailable: TransportError', $logs->text());
        $issuer->down = false;
        self::assertSame('consumer-client', $verifier->verify(Support::token())->azp);
    }

    public function testADiscoveryDocumentOfAnotherIssuerIsRefused(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $issuer->documentIssuer = 'https://evil.example.com/realms/x';

        self::assertSame('keys_unavailable', self::reason(Support::verifier($issuer), Support::token()));
        self::assertCount(1, $issuer->requests); // no key set is fetched
    }

    public function testOnlyRsaSigningKeysOfTwoThousandBitsOrMoreAreLoaded(): void
    {
        $small = KeyPair::generate('small', 1024);
        $encryption = Support::pair('enc')->jwk;
        $encryption['use'] = 'enc';
        $issuer = new FakeIssuer([Support::pair()], [
            $small->jwk,
            $encryption,
            ['kty' => 'EC', 'kid' => 'ec', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA'],
            ['kty' => 'RSA', 'kid' => 'broken', 'n' => 'AA', 'e' => 'AQAB'],
            'not a key',
        ]);
        $logs = Support::logs();
        $verifier = Support::verifier($issuer);

        self::assertSame('consumer-client', $verifier->verify(Support::token())->azp);
        self::assertSame('kid', self::reason($verifier, Support::token([], $small)));
        self::assertStringContainsString('apiable.key_skipped kid="small"', $logs->text());
        self::assertStringContainsString('apiable.key_skipped kid="broken"', $logs->text());
    }

    public function testACacheSharesTheKeySetBetweenProcesses(): void
    {
        $issuer = new FakeIssuer([Support::pair()]);
        $cache = new ArrayCache();
        $first = new TokenVerifier(Support::ISSUER, Support::RESOURCE, Support::ORG_ID, new SigningKeys(Support::ISSUER, $issuer, $cache));
        $first->verify(Support::token());
        self::assertSame(2, $issuer->count());

        // A second process, with empty memory, reads the cache and asks the issuer nothing.
        $second = new TokenVerifier(Support::ISSUER, Support::RESOURCE, Support::ORG_ID, new SigningKeys(Support::ISSUER, $issuer, $cache));
        self::assertSame(Status::Connected, $second->status());
        $second->verify(Support::token());
        self::assertSame(2, $issuer->count());
        self::assertStringNotContainsString('PRIVATE', serialize($cache->values));
    }

    public function testAnOrgIdThatIsNotAUuidIsRefusedAtOnce(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenVerifier(Support::ISSUER, Support::RESOURCE, 'my-org');
    }

    public function testEveryTokenGetsTheReasonThePythonSdkGives(): void
    {
        /** @var array{issuer: string, audience: string, org_id: string, key: array<string, mixed>, cases: list<array{name: string, token: string, reason: ?string}>, pyjwt: string, python: string} $fixture */
        $fixture = json_decode((string) file_get_contents(__DIR__ . '/fixtures/pyjwt_parity.json'), true);
        $issuer = new FakeIssuer([], [$fixture['key']], $fixture['issuer']);
        $verifier = new TokenVerifier(
            $fixture['issuer'],
            $fixture['audience'],
            $fixture['org_id'],
            new SigningKeys($fixture['issuer'], $issuer),
        );
        $differ = [];
        foreach ($fixture['cases'] as $case) {
            $actual = self::reason($verifier, $case['token']);
            if ($actual !== $case['reason']) {
                $differ[] = sprintf('%s: Python %s, PHP %s', $case['name'], json_encode($case['reason']), json_encode($actual));
            }
        }

        self::assertSame([], $differ, "PyJWT {$fixture['pyjwt']} on Python {$fixture['python']}");
        self::assertGreaterThanOrEqual(100, count($fixture['cases']));
        self::assertArrayNotHasKey('d', $fixture['key']);
    }
}
