<?php

declare(strict_types=1);

namespace Keelie\Middleware;

use Keelie\AiCatalog;
use Keelie\Internal\Responses;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Serves your AI Catalog at `/.well-known/ard.json` and
 * `/.well-known/ai-catalog.json`, with no token. Other requests pass untouched.
 *
 *     $app->add(new AiCatalogMiddleware(new AiCatalog($keelie, $metadata), $responseFactory));
 *
 * The order beside the token guards does not matter: once the catalog is made with
 * the metadata, the guards let a GET or a HEAD of its two paths pass.
 */
final class AiCatalogMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly AiCatalog $catalog,
        private readonly ResponseFactoryInterface $responses,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = $request->getMethod();
        $answer = $method === 'GET' || $method === 'HEAD'
            ? $this->catalog->answer($request->getUri()->getPath())
            : null;
        if ($answer === null) {
            return $handler->handle($request);
        }

        return Responses::make($this->responses, $answer->status, $answer->headers, $answer->body, $method === 'HEAD');
    }
}
