"""The Keelie SDK, by Apiable. In development, not released.

Source: https://github.com/apiable/keelie-sdk

It verifies tokens inside your own process, against the issuer's key set, which
it fetches and caches, and checks their scope against the route. It reports
usage in batches, in the background. It does not sit in the request path.
It serves the RFC 9728 metadata that tells an agent where to get a token.
One core checks the token for two adapters: a REST API and an MCP server.
"""

from apiable.discovery import MissingTokenChallenge, ProtectedResourceMetadata
from apiable.guard import TokenGuard
from apiable.mcp import McpGuard
from apiable.scopes import InsufficientScope, ScopeMap
from apiable.tokens import Claims, TokenRejected, TokenVerifier
from apiable.usage import UsageReporter

__version__ = "0.0.3"

__all__ = [
    "Claims",
    "InsufficientScope",
    "McpGuard",
    "MissingTokenChallenge",
    "ProtectedResourceMetadata",
    "ScopeMap",
    "TokenGuard",
    "TokenRejected",
    "TokenVerifier",
    "UsageReporter",
    "__version__",
]
