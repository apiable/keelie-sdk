<?php

declare(strict_types=1);

namespace Keelie;

/** The claims of a verified token that the SDK reads. */
final class Claims
{
    /**
     * @param string $azp the client the token was issued to: the credential. On a
     *                    token for a person, the agent's client. `sub` is ignored.
     * @param string $orgId your org id, lowercase with hyphens
     * @param list<string> $scopes the scopes of the token, each once
     * @param string|null $jti the token id. Log it. Never log the token.
     * @param \DateTimeImmutable $expiresAt when the token expires, from `exp`, in UTC.
     *                                      While keelie is down, the Consumer is served
     *                                      until then, and refused after.
     * @param string|null $consumerId on a token for a person, the Consumer whose credits
     *                                the person uses, lowercase with hyphens. Null on a
     *                                credential's token, which names its Consumer by
     *                                `azp`. Pass it to UsageReporter::record() with `azp`.
     */
    public function __construct(
        public readonly string $azp,
        public readonly string $orgId,
        public readonly array $scopes,
        public readonly ?string $jti,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly ?string $consumerId,
    ) {
    }

    /** True if the token carries this scope. */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
