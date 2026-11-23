<?php

declare(strict_types=1);

namespace Keelie;

/** No key in the set has this `kid`, after one refresh. */
final class UnknownKey extends \RuntimeException
{
}
