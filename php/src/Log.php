<?php

declare(strict_types=1);

namespace Keelie;

use Psr\Log\LoggerInterface;

/**
 * Where the SDK writes its log lines.
 *
 * Each line is one fixed event name and its fields, such as
 * `apiable.token_rejected reason=expired`. The names are the Python SDK's, so one
 * search finds an event in every language. No line holds a token, a secret or a
 * value taken from the request.
 *
 * By default a warning goes to PHP's `error_log()`, and `info` and `debug` are
 * dropped. Give your own PSR-3 logger with {@see Log::setLogger()}: Monolog and
 * the loggers of Laravel and Symfony all fit.
 */
final class Log
{
    private static ?LoggerInterface $logger = null;

    /** Send the SDK's log lines to `$logger`. Give null for the default. */
    public static function setLogger(?LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /** @internal */
    public static function debug(string $message): void
    {
        self::$logger?->debug($message);
    }

    /** @internal */
    public static function info(string $message): void
    {
        self::$logger?->info($message);
    }

    /** @internal */
    public static function warning(string $message): void
    {
        if (self::$logger !== null) {
            self::$logger->warning($message);
        } else {
            error_log($message);
        }
    }

    /** @internal The class of an error, for a log line. Never its message. */
    public static function errorName(\Throwable $error): string
    {
        $name = $error::class;
        $at = strrpos($name, '\\');

        return $at === false ? $name : substr($name, $at + 1);
    }
}
