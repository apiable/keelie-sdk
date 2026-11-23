<?php

declare(strict_types=1);

namespace Keelie\Internal;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Builds the answers the middleware gives itself.
 *
 * @internal
 */
final class Responses
{
    /** @param array<string, string> $headers */
    public static function make(
        ResponseFactoryInterface $factory,
        int $status,
        array $headers = [],
        string $body = '',
        bool $head = false,
    ): ResponseInterface {
        $response = $factory->createResponse($status);
        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        $response = $response->withHeader('Content-Length', (string) strlen($body));
        if (!$head && $body !== '') {
            $response->getBody()->write($body);
        }

        return $response;
    }
}
