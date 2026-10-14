"""The Keelie SDK, by Apiable. In development, not released.

Source: https://github.com/apiable/keelie-sdk

It verifies tokens inside your own process, against the issuer's key set, which
it fetches and caches, and checks their scope against the route. It does not
sit in the request path.
"""

from apiable.scopes import InsufficientScope, ScopeMap
from apiable.tokens import Claims, TokenRejected, TokenVerifier

__version__ = "0.0.3"

__all__ = [
    "Claims",
    "InsufficientScope",
    "ScopeMap",
    "TokenRejected",
    "TokenVerifier",
    "__version__",
]
