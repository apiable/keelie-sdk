<?php

declare(strict_types=1);

namespace Keelie\Internal;

/**
 * JSON as the Python SDK reads it.
 *
 * PHP's json_decode() differs from Python's json module. It refuses NaN and
 * Infinity, it reads no UTF-16 or UTF-32 text, and it cannot tell an empty
 * object from an empty list. So the SDK reads JSON with this parser.
 *
 * An object is a {@see JsonObject}. A list is a PHP list. A string is UTF-8.
 *
 * @internal
 */
final class Json
{
    /** Deeper than this is refused, as Python's parser refuses it at its recursion limit. */
    public const MAX_DEPTH = 1000;

    private string $text;
    private int $at = 0;
    private int $length;
    private int $depth = 0;

    private function __construct(string $text, private readonly bool $refuseDuplicates)
    {
        $this->text = $text;
        $this->length = strlen($text);
    }

    /**
     * The value of `$bytes`, read as Python's `json.loads` reads bytes.
     *
     * It reads a UTF-16 or UTF-32 text, and one UTF-8 byte order mark, as Python's
     * `json.detect_encoding` does. A key given twice keeps its last value.
     *
     * @throws JsonError
     */
    public static function lenient(string $bytes): mixed
    {
        return (new self(self::pythonDecode($bytes), false))->document();
    }

    /**
     * The value of `$text`. It must be UTF-8, with no byte order mark.
     *
     * Two parsers can pick different values for a key given twice. A guard that
     * read one tool name while your server read another would check the wrong
     * scope. So a key given twice in one object throws {@see DuplicateKey}. Keys
     * compare after their escapes are read.
     *
     * @throws JsonError
     */
    public static function strict(string $text): mixed
    {
        return (new self(self::utf8($text), true))->document();
    }

    /** `$bytes` as UTF-8, decoded as Python's `json.loads` decodes bytes. */
    private static function pythonDecode(string $bytes): string
    {
        if (str_starts_with($bytes, "\xEF\xBB\xBF")) {
            return self::utf8(substr($bytes, 3));
        }
        $encoding = match (true) {
            str_starts_with($bytes, "\x00\x00\xFE\xFF") => ['32', true, 4],
            str_starts_with($bytes, "\xFF\xFE\x00\x00") => ['32', false, 4],
            str_starts_with($bytes, "\xFE\xFF") => ['16', true, 2],
            str_starts_with($bytes, "\xFF\xFE") => ['16', false, 2],
            default => null,
        };
        if ($encoding !== null) {
            [$width, $bigEndian, $bom] = $encoding;
            $body = substr($bytes, $bom);

            return self::utf8($width === '32' ? self::fromUtf32($body, $bigEndian) : self::fromUtf16($body, $bigEndian));
        }
        $length = strlen($bytes);
        if ($length >= 4) {
            if ($bytes[0] === "\x00") {
                return self::utf8($bytes[1] !== "\x00" ? self::fromUtf16($bytes, true) : self::fromUtf32($bytes, true));
            }
            if ($bytes[1] === "\x00") {
                return self::utf8($bytes[2] !== "\x00" || $bytes[3] !== "\x00"
                    ? self::fromUtf16($bytes, false)
                    : self::fromUtf32($bytes, false));
            }
        } elseif ($length === 2) {
            if ($bytes[0] === "\x00") {
                return self::utf8(self::fromUtf16($bytes, true));
            }
            if ($bytes[1] === "\x00") {
                return self::utf8(self::fromUtf16($bytes, false));
            }
        }

        return self::utf8($bytes);
    }

    /** The text, if it is UTF-8 with no byte order mark. Python's json module refuses both. */
    private static function utf8(string $text): string
    {
        if (preg_match('//u', $text) !== 1) {
            throw new JsonError('not UTF-8');
        }
        if (str_starts_with($text, "\xEF\xBB\xBF")) {
            throw new JsonError('byte order mark');
        }

        return $text;
    }

    private static function fromUtf16(string $bytes, bool $bigEndian): string
    {
        if (strlen($bytes) % 2 !== 0) {
            throw new JsonError('not UTF-16');
        }
        $units = array_values(unpack($bigEndian ? 'n*' : 'v*', $bytes) ?: []);
        $text = '';
        $count = count($units);
        for ($i = 0; $i < $count; $i++) {
            $unit = $units[$i];
            if ($unit >= 0xD800 && $unit <= 0xDBFF) {
                $low = $units[$i + 1] ?? null;
                if ($low === null || $low < 0xDC00 || $low > 0xDFFF) {
                    // Python reads a lone surrogate. The SDK refuses it.
                    throw new JsonError('lone surrogate');
                }
                $text .= self::codePoint(0x10000 + (($unit - 0xD800) << 10) + ($low - 0xDC00));
                $i++;
            } elseif ($unit >= 0xDC00 && $unit <= 0xDFFF) {
                throw new JsonError('lone surrogate');
            } else {
                $text .= self::codePoint($unit);
            }
        }

        return $text;
    }

    private static function fromUtf32(string $bytes, bool $bigEndian): string
    {
        if (strlen($bytes) % 4 !== 0) {
            throw new JsonError('not UTF-32');
        }
        $text = '';
        foreach (unpack($bigEndian ? 'N*' : 'V*', $bytes) ?: [] as $code) {
            if ($code > 0x10FFFF || ($code >= 0xD800 && $code <= 0xDFFF)) {
                throw new JsonError('not UTF-32');
            }
            $text .= self::codePoint($code);
        }

        return $text;
    }

    private static function codePoint(int $code): string
    {
        return match (true) {
            $code < 0x80 => chr($code),
            $code < 0x800 => chr(0xC0 | ($code >> 6)) . chr(0x80 | ($code & 0x3F)),
            $code < 0x10000 => chr(0xE0 | ($code >> 12)) . chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F)),
            default => chr(0xF0 | ($code >> 18)) . chr(0x80 | (($code >> 12) & 0x3F))
                . chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F)),
        };
    }

    private function document(): mixed
    {
        $this->whitespace();
        $value = $this->value();
        $this->whitespace();
        if ($this->at !== $this->length) {
            throw new JsonError('extra data');
        }

        return $value;
    }

    private function whitespace(): void
    {
        $this->at += strspn($this->text, " \t\n\r", $this->at);
    }

    private function value(): mixed
    {
        $c = $this->text[$this->at] ?? '';

        return match (true) {
            $c === '{' => $this->object(),
            $c === '[' => $this->list(),
            $c === '"' => $this->string(),
            $this->literal('true') => true,
            $this->literal('false') => false,
            $this->literal('null') => null,
            $this->literal('NaN') => NAN,
            $this->literal('Infinity') => INF,
            $this->literal('-Infinity') => -INF,
            default => $this->number(),
        };
    }

    private function literal(string $word): bool
    {
        if (substr_compare($this->text, $word, $this->at, strlen($word)) === 0) {
            $this->at += strlen($word);

            return true;
        }

        return false;
    }

    private function number(): int|float
    {
        if (preg_match('/-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/A', $this->text, $match, 0, $this->at) !== 1) {
            throw new JsonError('expecting a value');
        }
        $this->at += strlen($match[0]);
        if (($match[1] ?? '') === '' && ($match[2] ?? '') === '') {
            $int = filter_var($match[0], FILTER_VALIDATE_INT);

            // Python's int has no limit. A larger whole number is read as a float.
            return $int === false ? (float) $match[0] : $int;
        }

        return (float) $match[0];
    }

    private function enter(): void
    {
        if (++$this->depth > self::MAX_DEPTH) {
            throw new JsonError('nested too deeply');
        }
        $this->at++;
        $this->whitespace();
    }

    private function object(): JsonObject
    {
        $this->enter();
        $members = [];
        if (($this->text[$this->at] ?? '') === '}') {
            $this->at++;
            $this->depth--;

            return new JsonObject($members);
        }
        while (true) {
            if (($this->text[$this->at] ?? '') !== '"') {
                throw new JsonError('expecting a key');
            }
            $key = $this->string();
            if ($this->refuseDuplicates && array_key_exists($key, $members)) {
                throw new DuplicateKey('a key given twice');
            }
            $this->whitespace();
            if (($this->text[$this->at] ?? '') !== ':') {
                throw new JsonError('expecting a colon');
            }
            $this->at++;
            $this->whitespace();
            $members[$key] = $this->value();
            $this->whitespace();
            $c = $this->text[$this->at] ?? '';
            $this->at++;
            if ($c === '}') {
                $this->depth--;

                return new JsonObject($members);
            }
            if ($c !== ',') {
                throw new JsonError('expecting a comma');
            }
            $this->whitespace();
        }
    }

    /** @return list<mixed> */
    private function list(): array
    {
        $this->enter();
        $items = [];
        if (($this->text[$this->at] ?? '') === ']') {
            $this->at++;
            $this->depth--;

            return $items;
        }
        while (true) {
            $items[] = $this->value();
            $this->whitespace();
            $c = $this->text[$this->at] ?? '';
            $this->at++;
            if ($c === ']') {
                $this->depth--;

                return $items;
            }
            if ($c !== ',') {
                throw new JsonError('expecting a comma');
            }
            $this->whitespace();
        }
    }

    private function string(): string
    {
        $this->at++;
        $out = '';
        while (true) {
            $run = strcspn($this->text, "\"\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                . "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F", $this->at);
            $out .= substr($this->text, $this->at, $run);
            $this->at += $run;
            $c = $this->text[$this->at] ?? '';
            if ($c === '"') {
                $this->at++;

                return $out;
            }
            if ($c !== '\\') {
                throw new JsonError($c === '' ? 'unterminated string' : 'control character in a string');
            }
            $escape = $this->text[$this->at + 1] ?? '';
            $this->at += 2;
            $out .= match ($escape) {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => "\x08",
                'f' => "\x0C",
                'n' => "\n",
                'r' => "\r",
                't' => "\t",
                'u' => $this->unicodeEscape(),
                default => throw new JsonError('invalid escape'),
            };
        }
    }

    private function unicodeEscape(): string
    {
        $unit = $this->hex();
        if ($unit >= 0xD800 && $unit <= 0xDBFF && substr_compare($this->text, '\\u', $this->at, 2) === 0) {
            $this->at += 2;
            $low = $this->hex();
            if ($low >= 0xDC00 && $low <= 0xDFFF) {
                return self::codePoint(0x10000 + (($unit - 0xD800) << 10) + ($low - 0xDC00));
            }
        }
        if ($unit >= 0xD800 && $unit <= 0xDFFF) {
            // Python reads a lone surrogate. The SDK refuses it.
            throw new JsonError('lone surrogate');
        }

        return self::codePoint($unit);
    }

    private function hex(): int
    {
        $hex = substr($this->text, $this->at, 4);
        if (strlen($hex) !== 4 || !ctype_xdigit($hex)) {
            throw new JsonError('invalid escape');
        }
        $this->at += 4;

        return (int) hexdec($hex);
    }
}
