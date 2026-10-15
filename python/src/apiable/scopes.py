"""Check the scope of a verified token against the route it calls.

You give the SDK one map: for each route, the scope a token must carry. A route
is the HTTP method and the path template your framework matched, such as
``("GET", "/orders/{order_id}")``. Pass the template, not the path of the
request, so that one entry covers every order.

The check is strict:

- A scope matches only itself. ``orders:read`` does not grant ``orders``, and
  ``orders`` does not grant ``orders:read``.
- A route matches only itself. There is no prefix and no wildcard.
- A route that is not in the map is refused. Add every route that a token may
  call.

Every refusal raises :class:`InsufficientScope`. Answer it with ``403``, not
``401``: the token is good, it does not allow this call.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from apiable.tokens import Claims

logger = logging.getLogger(__name__)


class InsufficientScope(Exception):
    """The token does not carry the scope the route requires."""

    def __init__(self, method: str, route: str) -> None:
        super().__init__(f"{method} {route}")
        self.method = method
        self.route = route


class ScopeMap:
    """The scope that each route requires."""

    def __init__(self, routes: Mapping[tuple[str, str], str]) -> None:
        self._routes: dict[tuple[str, str], str] = {}
        for (method, route), scope in routes.items():
            # One scope, by the rule that splits the token's scope claim.
            if not isinstance(scope, str) or scope.split() != [scope]:
                raise ValueError(f"not one scope: {scope!r} for {method} {route}")
            key = (method.upper(), route)
            if key in self._routes:
                raise ValueError(f"route given twice: {method} {route}")
            self._routes[key] = scope

    def check(self, claims: Claims, method: str, route: str) -> None:
        """Return if the token may call the route, else raise :class:`InsufficientScope`."""
        method = method.upper()
        required = self._routes.get((method, route))
        if required is None or required not in claims.scopes:
            logger.info(
                "apiable.scope_refused reason=%s client=%s method=%s route=%s",
                "unmapped" if required is None else "scope",
                claims.azp,
                method,
                # A route that is not in the map can come from the request,
                # such as an MCP tool name, and stays out of the log.
                route if required is not None else "-",
            )
            raise InsufficientScope(method, route)
