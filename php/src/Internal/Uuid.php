<?php

declare(strict_types=1);

namespace Keelie\Internal;

/**
 * The UUID rules the Python SDK gets from its standard library.
 *
 * {@see parse()} reads a UUID as Python's `uuid.UUID(str)` does, so the SDKs
 * accept and refuse the same values. {@see v5()} makes the same key from the same
 * namespace and name as Python's `uuid.uuid5`.
 *
 * @internal
 */
final class Uuid
{
    /** The UUID in its canonical form, lowercase with hyphens, or null if it is not one. */
    public static function parse(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        // Python's order: drop "urn:" and "uuid:", the braces, then every hyphen.
        $hex = str_replace(['urn:', 'uuid:'], '', $value);
        $hex = str_replace('-', '', trim($hex, '{}'));
        if (preg_match('/^[0-9a-fA-F]{32}$/D', $hex) !== 1) {
            return null;
        }

        return self::format(strtolower($hex));
    }

    /** The name-based UUID of RFC 9562, version 5 (SHA-1). */
    public static function v5(string $namespace, string $name): string
    {
        $ns = self::parse($namespace) ?? throw new \InvalidArgumentException('namespace is not a UUID');
        $digest = sha1(hex2bin(str_replace('-', '', $ns)) . $name, true);
        $digest[6] = chr((ord($digest[6]) & 0x0F) | 0x50);
        $digest[8] = chr((ord($digest[8]) & 0x3F) | 0x80);

        return self::format(bin2hex(substr($digest, 0, 16)));
    }

    /** A random UUID, version 4. */
    public static function v4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return self::format(bin2hex($bytes));
    }

    private static function format(string $hex): string
    {
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-'
            . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
    }
}
