<?php

declare(strict_types=1);

namespace Keelie\Internal;

use Keelie\AiCatalog;
use Keelie\ProtectedResourceMetadata;

/**
 * Which requests a guard checks.
 *
 * The path compared is the path of the request's URI, as the client sent it. A
 * router can route it in another form: with its escapes read, its dot segments
 * resolved and its doubled slashes folded, without a format extension such as
 * `.json`, or without case. A request that is under `resource` in any of these
 * forms is guarded. The guard can only guard more than your router serves, never
 * less.
 *
 * @internal
 */
final class PathForms
{
    /** The most forms of one path the guard compares, besides the fully normalized one. */
    public const MAX_FORMS = 128;
    /**
     * The longest path whose forms the guard makes. A longer path that a router
     * could read in another form is guarded, wherever it points: making its forms
     * would cost each request too much time, before any token is checked.
     */
    public const MAX_FORMS_PATH_BYTES = 256;

    /**
     * True for a request under `resource` that must carry a token.
     *
     * A CORS preflight (OPTIONS) and every path outside `resource` pass. So does a
     * GET or a HEAD of the metadata, and of the AI Catalog at either of its paths
     * when the catalog serves it. Any other method on those paths needs a token.
     */
    public static function guarded(string $method, string $path, ProtectedResourceMetadata $metadata): bool
    {
        if ($method === 'OPTIONS') {
            return false;
        }
        if (
            in_array($method, ['GET', 'HEAD'], true)
            && ($path === $metadata->path || ($metadata->aiCatalog && isset(AiCatalog::MEDIA_TYPES[$path])))
        ) {
            return false;
        }
        $prefixes = array_values(array_unique([
            strtolower($metadata->prefix),
            strtolower(self::unescape($metadata->prefix)),
        ]));
        if (in_array('', $prefixes, true)) {
            return true;
        }
        if (strlen($path) > self::MAX_FORMS_PATH_BYTES && !self::plain($path)) {
            return true;
        }
        foreach (self::forms($path) as $form) {
            $form = strtolower($form);
            foreach ($prefixes as $prefix) {
                if ($form === $prefix || str_starts_with($form, "{$prefix}/")) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The forms of `$path` a router could route by: each step of each
     * normalization a router makes, alone and in turn, and the path with all of
     * them made until nothing changes.
     *
     * @return list<string>
     */
    public static function forms(string $path): array
    {
        // Every step leaves a plain path as it is.
        if (self::plain($path)) {
            return [$path];
        }
        $seen = [$path => true];
        $queue = [$path];
        while ($queue !== [] && count($seen) < self::MAX_FORMS) {
            foreach (self::steps(array_shift($queue)) as $form) {
                if (!isset($seen[$form])) {
                    $seen[$form] = true;
                    $queue[] = $form;
                }
            }
        }

        return [...array_map('strval', array_keys($seen)), ...self::normalized($path)];
    }

    /** True for a path that has one form only: it starts with a slash, and has no escape, no dot, no backslash and no doubled slash. */
    public static function plain(string $path): bool
    {
        return str_starts_with($path, '/') && !str_contains($path, '//') && strpbrk($path, '%.\\') === false;
    }

    /**
     * One normalization each: a leading slash, escapes read, backslashes as
     * slashes, dot segments resolved, doubled slashes folded, and a format
     * extension dropped.
     *
     * @return list<string>
     */
    private static function steps(string $form): array
    {
        return [
            str_starts_with($form, '/') ? $form : "/{$form}",
            self::unescape($form),
            str_replace('\\', '/', $form),
            self::resolveDots($form),
            self::squeeze($form),
            self::dropExtension($form),
        ];
    }

    /**
     * Every step made, over and over, until nothing changes: with and without the
     * format extension dropped.
     *
     * @return list<string>
     */
    private static function normalized(string $path): array
    {
        $form = $path;
        for ($i = 0; $i < 8; $i++) {
            $next = self::squeeze('/' . self::resolveDots(str_replace('\\', '/', self::unescape($form))));
            if ($next === $form) {
                break;
            }
            $form = $next;
        }

        return [$form, self::dropExtension($form)];
    }

    public static function unescape(string $text): string
    {
        return (string) preg_replace_callback(
            '/%[0-9a-fA-F]{2}/',
            static fn (array $match): string => chr((int) hexdec(substr($match[0], 1))),
            $text,
        );
    }

    private static function squeeze(string $form): string
    {
        return (string) preg_replace('#/{2,}#', '/', $form);
    }

    private static function dropExtension(string $form): string
    {
        return (string) preg_replace('#\.[^/]*$#D', '', $form);
    }

    /** The path with its "." and ".." segments resolved (RFC 3986, section 5.2.4). */
    private static function resolveDots(string $path): string
    {
        $output = [];
        $segments = explode('/', $path);
        $last = count($segments) - 1;
        foreach ($segments as $index => $segment) {
            if ($segment === '.') {
                if ($index === $last) {
                    $output[] = '';
                }
            } elseif ($segment === '..') {
                if (count($output) > 1) {
                    array_pop($output);
                }
                if ($index === $last) {
                    $output[] = '';
                }
            } else {
                $output[] = $segment;
            }
        }

        return implode('/', $output);
    }
}
