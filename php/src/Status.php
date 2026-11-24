<?php

declare(strict_types=1);

namespace Keelie;

/** What the SDK knows of the issuer, from its last fetch of the key set. */
enum Status: string
{
    /** The last fetch worked. */
    case Connected = 'connected';
    /** The last fetch failed. The keys in hand go on verifying. */
    case Degraded = 'degraded';
    /** No key in hand, so every token is refused. */
    case Offline = 'offline';
}
