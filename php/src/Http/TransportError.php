<?php

declare(strict_types=1);

namespace Keelie\Http;

/** The request did not get an answer: a network error, a timeout or a redirect. */
final class TransportError extends \RuntimeException
{
}
