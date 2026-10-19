from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from apiable import Claims, InsufficientScope, ScopeMap, TokenRejected

ORG_ID = uuid.UUID("01890000-0000-7000-8000-000000000001")

SCOPES = ScopeMap(
    {
        ("GET", "/orders/{order_id}"): "orders:read",
        ("POST", "/orders"): "orders:write",
    }
)


def _claims(scope: str) -> Claims:
    return Claims(
        azp="client-1",
        org_id=ORG_ID,
        scopes=frozenset(scope.split()),
        jti=None,
        expires_at=datetime.now(timezone.utc),
    )


@pytest.mark.parametrize(
    ("method", "route"),
    [("GET", "/orders/{order_id}"), ("get", "/orders/{order_id}"), ("POST", "/orders")],
)
def test_a_token_with_the_scope_passes(method: str, route: str) -> None:
    SCOPES.check(_claims("orders:read orders:write"), method, route)


@pytest.mark.parametrize(
    ("scope", "method", "route"),
    [
        # No scope, or another route's scope.
        ("", "GET", "/orders/{order_id}"),
        ("orders:write", "GET", "/orders/{order_id}"),
        # A scope matches only itself: no prefix, no parent.
        ("orders", "GET", "/orders/{order_id}"),
        ("orders:read:all", "GET", "/orders/{order_id}"),
        # A route matches only itself: another method, a concrete path, a sub-path.
        ("orders:read orders:write", "DELETE", "/orders/{order_id}"),
        ("orders:read orders:write", "GET", "/orders/42"),
        ("orders:read orders:write", "POST", "/orders/"),
        ("orders:read orders:write", "POST", "/orders/{order_id}/items"),
    ],
)
def test_a_token_without_the_scope_is_refused(scope: str, method: str, route: str) -> None:
    with pytest.raises(InsufficientScope) as refused:
        SCOPES.check(_claims(scope), method, route)
    # A 403, not a 401: a caller that maps TokenRejected to 401 must not catch it.
    assert not isinstance(refused.value, TokenRejected)


def test_the_method_in_the_map_is_case_insensitive() -> None:
    ScopeMap({("get", "/orders"): "orders:read"}).check(_claims("orders:read"), "GET", "/orders")


@pytest.mark.parametrize(
    "scope",
    [
        "",
        "   ",
        " orders:read",
        "orders:read ",
        "orders:read orders:write",
        "orders:read\torders:write",
    ],
)
def test_a_route_requires_exactly_one_scope(scope: str) -> None:
    with pytest.raises(ValueError, match="not one scope"):
        ScopeMap({("GET", "/orders"): scope})


def test_a_route_given_twice_is_refused() -> None:
    # The method is case-insensitive, so these two are one route with two scopes.
    with pytest.raises(ValueError, match="route given twice"):
        ScopeMap({("get", "/orders"): "orders:write", ("GET", "/orders"): "orders:read"})
