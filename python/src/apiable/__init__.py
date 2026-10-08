"""The Keelie SDK, by Apiable: placeholder.

This package reserves the name on PyPI. The SDK is in development and is not
released. Source: https://github.com/apiable/keelie-sdk

When released, this will be a FastAPI dependency that verifies tokens locally
against a cached key set, enforces scopes per route, and reports usage back in
batches after the response. It does not sit in the request path.
"""

from typing import NoReturn

__version__ = "0.0.3"

_NOT_RELEASED = (
    "The Keelie SDK, by Apiable, is not released yet; this package only reserves the name.\n"
    "\n"
    "When it ships it will be a FastAPI dependency that verifies tokens inside your\n"
    "own process, enforces scopes per route, and reports usage in batches after the\n"
    "response.\n"
    "\n"
    "Source: https://github.com/apiable/keelie-sdk\n"
    "Progress and early access: https://apiable.io\n"
)


def __getattr__(name: str) -> NoReturn:
    # PEP 562. Makes `from apiable import Apiable` explain itself rather than
    # raising a bare ImportError.
    raise NotImplementedError(_NOT_RELEASED)
