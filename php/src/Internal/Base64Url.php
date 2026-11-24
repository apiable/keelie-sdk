<?php

declare(strict_types=1);

namespace Keelie\Internal;

/**
 * Base64url, read strictly as PyJWT reads a token's segments.
 *
 * @internal
 */
final class Base64Url
{
    /**
     * The bytes of `$segment`, or null.
     *
     * Up to two "=" of padding are allowed, on a segment whose length is then a
     * multiple of four. Every other character must be in the URL-safe alphabet,
     * and the text must be the one canonical encoding of its bytes.
     */
    public static function decode(string $segment): ?string
    {
        $stripped = rtrim($segment, '=');
        $padding = strlen($segment) - strlen($stripped);
        if ($padding > 2 || ($padding > 0 && strlen($segment) % 4 !== 0)) {
            return null;
        }
        if (strlen($stripped) % 4 === 1 || preg_match('/^[A-Za-z0-9_-]*$/D', $stripped) !== 1) {
            return null;
        }
        $bytes = base64_decode(strtr($stripped, '-_', '+/'), true);
        if ($bytes === false || self::encode($bytes) !== $stripped) {
            return null;
        }

        return $bytes;
    }

    /** The bytes of a key's member, read as PyJWT reads it: padding and other characters are passed over. */
    public static function decodeMember(string $value): string
    {
        $standard = preg_replace('/[^A-Za-z0-9+\/]/', '', strtr($value, '-_', '+/')) ?? '';

        return (string) base64_decode($standard . str_repeat('=', (4 - strlen($standard) % 4) % 4));
    }

    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
