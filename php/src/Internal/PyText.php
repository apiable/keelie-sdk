<?php

declare(strict_types=1);

namespace Keelie\Internal;

/**
 * Text rules the Python SDK gets from Python itself.
 *
 * @internal
 */
final class PyText
{
    /** What Python's `str.split()` splits on. */
    private const WHITESPACE = '/[\t\n\x{0B}\f\r\x{1C}-\x{1F} \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}'
        . '\x{202F}\x{205F}\x{3000}]+/u';

    /**
     * The words of `$text`, as Python's `str.split()` gives them.
     *
     * @return list<string>
     */
    public static function split(string $text): array
    {
        $words = preg_split(self::WHITESPACE, $text, -1, PREG_SPLIT_NO_EMPTY);

        return $words === false ? [] : $words;
    }

    /** One scope, by the rule that splits the token's scope claim. */
    public static function isOneScope(mixed $scope): bool
    {
        return is_string($scope) && preg_match('//u', $scope) === 1 && self::split($scope) === [$scope];
    }
}
