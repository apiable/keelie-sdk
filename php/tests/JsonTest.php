<?php

declare(strict_types=1);

namespace Keelie\Tests;

use Keelie\Internal\DuplicateKey;
use Keelie\Internal\Json;
use Keelie\Internal\JsonError;
use Keelie\Internal\JsonObject;
use Keelie\Internal\Uuid;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JsonTest extends TestCase
{
    public function testItReadsJsonAsPythonDoes(): void
    {
        $value = Json::lenient('{"a": [1, 2.5, -0, true, null, "é😀"], "b": {}, "c": [], "a2": NaN, "x": 1, "x": 2}');

        self::assertInstanceOf(JsonObject::class, $value);
        self::assertSame([1, 2.5, 0, true, null, "é😀"], $value->get('a'));
        self::assertInstanceOf(JsonObject::class, $value->get('b'));
        self::assertSame([], $value->get('c'));
        self::assertNan($value->get('a2'));
        self::assertSame(2, $value->get('x'));
    }

    public function testItReadsUtf16AndUtf32AsPythonDoes(): void
    {
        $text = '{"k": "v"}';
        $utf16 = "\xFF\xFE" . implode('', array_map(static fn (string $c): string => $c . "\0", str_split($text)));
        $utf32be = implode('', array_map(static fn (string $c): string => "\0\0\0" . $c, str_split($text)));

        self::assertSame('v', Json::lenient($utf16)->get('k'));
        self::assertSame('v', Json::lenient($utf32be)->get('k'));
        self::assertSame('v', Json::lenient("\xEF\xBB\xBF" . $text)->get('k'));
    }

    /** @return iterable<string, array{string}> */
    public static function notJson(): iterable
    {
        yield 'empty' => [''];
        yield 'a comment' => ['{} // x'];
        yield 'a trailing comma' => ['[1,]'];
        yield 'single quotes' => ["{'a': 1}"];
        yield 'a control character' => ["\"a\tb\""];
        yield 'an invalid escape' => ['"\x"'];
        yield 'a lone surrogate' => ['"\ud800"'];
        yield 'a leading zero' => ['01'];
        yield 'extra data' => ['{} {}'];
        yield 'too deep' => [str_repeat('[', 1001) . str_repeat(']', 1001)];
    }

    #[DataProvider('notJson')]
    public function testItRefusesWhatPythonRefuses(string $text): void
    {
        $this->expectException(JsonError::class);
        Json::lenient($text);
    }

    public function testStrictRefusesAKeyGivenTwiceAfterItsEscapesAreRead(): void
    {
        $this->expectException(DuplicateKey::class);
        Json::strict('{"name": 1, "name": 2}');
    }

    public function testStrictRefusesAByteOrderMark(): void
    {
        $this->expectException(JsonError::class);
        Json::strict("\xEF\xBB\xBF{}");
    }

    public function testUuidsAreReadAsPythonReadsThem(): void
    {
        $canonical = '6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12';
        foreach (['6C7A6F0E-4A8B-4C2D-9A51-0B3E5D7F9A12', '6c7a6f0e4a8b4c2d9a510b3e5d7f9a12', "{{$canonical}}", "urn:uuid:{$canonical}"] as $form) {
            self::assertSame($canonical, Uuid::parse($form));
        }
        self::assertNull(Uuid::parse('6c7a6f0e-4a8b'));
        self::assertNull(Uuid::parse(7));
    }
}
