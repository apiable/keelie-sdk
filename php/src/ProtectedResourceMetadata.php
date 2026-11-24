<?php

declare(strict_types=1);

namespace Keelie;

use Keelie\Internal\PyText;

/**
 * The RFC 9728 metadata of your API, and the challenge that points to it.
 *
 * Two standard pieces, served from your own domain:
 *
 * - The protected resource metadata (RFC 9728). It names your API and the one
 *   issuer that mints tokens for it. An agent reads it at the well-known address
 *   of your API. For `https://api.example.com/mcp` that is
 *   `https://api.example.com/.well-known/oauth-protected-resource/mcp`.
 * - A 401 with `WWW-Authenticate: Bearer resource_metadata="..."` on a request
 *   that carries no token (RFC 6750, RFC 9728 section 5). An agent finds the
 *   metadata from this refusal. It does not read the header on a 200.
 *
 * The issuer serves its own authorization server metadata (RFC 8414). The SDK
 * does not copy it: it names the issuer, and the agent reads the issuer.
 */
final class ProtectedResourceMetadata
{
    public const WELL_KNOWN = '/.well-known/oauth-protected-resource';

    /** The URL an agent types for your API, exactly, path included. */
    public readonly string $resource;
    /** Where the metadata is served on your host, such as `/.well-known/oauth-protected-resource/v1`. */
    public readonly string $path;
    /** The full URL of the metadata, from the configuration, never from the request's Host. */
    public readonly string $url;
    /** The JSON document, as served. */
    public readonly string $document;
    /** @internal The path of `resource`, with no final slash: "" at the root. */
    public readonly string $prefix;
    /**
     * Set by {@see AiCatalog} when it is made with this metadata. Until then the
     * catalog paths are guarded like any other.
     */
    public bool $aiCatalog = false;

    /**
     * @param string $resource your API's address, exactly as registered: https, a
     *                         lowercase host, no user, query, fragment or final slash
     * @param string $authorizationServer the issuer, the same value you give TokenVerifier.
     *                                    It is one issuer: an agent uses the first and does not try a second.
     * @param list<string>|null $scopesSupported published only if you give it
     *
     * @throws \InvalidArgumentException for a value that breaks these rules
     */
    public function __construct(string $resource, string $authorizationServer, ?array $scopesSupported = null)
    {
        [$netloc, $resourcePath] = self::httpsUrl('resource', $resource);
        self::httpsUrl('authorizationServer', $authorizationServer);
        $this->resource = $resource;
        // The well-known name goes between the host and the path (RFC 9728 section 3.1).
        $this->prefix = in_array($resourcePath, ['', '/'], true) ? '' : rtrim($resourcePath, '/');
        $this->path = self::WELL_KNOWN . $this->prefix;
        $this->url = "https://{$netloc}{$this->path}";
        $document = [
            'resource' => $resource,
            'authorization_servers' => [$authorizationServer],
            'bearer_methods_supported' => ['header'],
        ];
        if ($scopesSupported !== null) {
            if (!array_is_list($scopesSupported)) {
                throw new \InvalidArgumentException('give a list of scopes: ' . json_encode($scopesSupported));
            }
            foreach ($scopesSupported as $scope) {
                if (!PyText::isOneScope($scope)) {
                    throw new \InvalidArgumentException('not one scope each: ' . json_encode($scopesSupported));
                }
            }
            $document['scopes_supported'] = $scopesSupported;
        }
        $this->document = json_encode($document, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /**
     * The `WWW-Authenticate` value. Give `"invalid_token"` for a refused token, and
     * `"insufficient_scope"` for a token that lacks the scope.
     */
    public function challenge(?string $error = null): string
    {
        if ($error === null) {
            return "Bearer resource_metadata=\"{$this->url}\"";
        }
        if (preg_match('/^[a-z_]+$/D', $error) !== 1) {
            throw new \InvalidArgumentException('not an RFC 6750 error code: ' . json_encode($error));
        }

        return "Bearer error=\"{$error}\", resource_metadata=\"{$this->url}\"";
    }

    /** True for the path of `resource` and every path below it. */
    public function protects(string $path): bool
    {
        return $this->prefix === '' || $path === $this->prefix || str_starts_with($path, "{$this->prefix}/");
    }

    /** The Bearer token in an `Authorization` header value, or null. The token is not checked. */
    public static function bearerToken(?string $authorization): ?string
    {
        if ($authorization === null) {
            return null;
        }
        $value = trim($authorization);
        $at = strpos($value, ' ');
        $scheme = $at === false ? $value : substr($value, 0, $at);
        $token = $at === false ? '' : trim(substr($value, $at + 1));

        return strcasecmp($scheme, 'bearer') === 0 && $token !== '' ? $token : null;
    }

    /**
     * The host part and the path of `$value`, if it is an https URL with a host and
     * no user, query, fragment or final slash.
     *
     * The scheme and the host must be lowercase: an uppercase one is refused, not
     * folded. keelie stores your `resource` with the same rule and puts it into
     * `aud` exactly, so the value here and the `aud` of a token compare equal.
     *
     * @return array{string, string}
     */
    private static function httpsUrl(string $name, string $value): array
    {
        // Printable ASCII with no space, quote or backslash: the URL goes inside a
        // quoted string of the header, as it is.
        if (preg_match('/^[!#-\[\]-~]+$/D', $value) !== 1) {
            throw new \InvalidArgumentException("{$name} is not a URL: " . json_encode($value));
        }
        $shape = new \InvalidArgumentException(
            "{$name} must be https, with a host, no user, query, fragment or final slash: " . json_encode($value)
        );
        if (strncasecmp($value, 'https://', 8) !== 0 || str_contains($value, '?') || str_contains($value, '#')) {
            throw $shape;
        }
        $rest = substr($value, 8);
        $slash = strpos($rest, '/');
        $netloc = $slash === false ? $rest : substr($rest, 0, $slash);
        $path = $slash === false ? '' : substr($rest, $slash);
        if (str_contains($netloc, '@')) {
            throw $shape;
        }
        if (str_starts_with($netloc, '[')) {
            // An IPv6 address, then perhaps a port.
            $close = strpos($netloc, ']');
            if ($close === false) {
                throw $shape;
            }
            $host = substr($netloc, 0, $close + 1);
            $after = substr($netloc, $close + 1);
            if ($after !== '' && !str_starts_with($after, ':')) {
                throw $shape;
            }
            $port = $after === '' ? null : substr($after, 1);
        } else {
            $colon = strpos($netloc, ':');
            $host = $colon === false ? $netloc : substr($netloc, 0, $colon);
            $port = $colon === false ? null : substr($netloc, $colon + 1);
        }
        if ($host === '' || $host === '[]') {
            throw $shape;
        }
        if ($port !== null && $port !== '' && !(ctype_digit($port) && (int) $port <= 65535)) {
            throw new \InvalidArgumentException("{$name} has a port that is not a number: " . json_encode($value));
        }
        if (!in_array($path, ['', '/'], true) && str_ends_with($path, '/')) {
            throw $shape;
        }
        if (!str_starts_with($value, 'https://') || $netloc !== strtolower($netloc)) {
            throw new \InvalidArgumentException("{$name} must have a lowercase scheme and host: " . json_encode($value));
        }

        return [$netloc, $path];
    }
}
