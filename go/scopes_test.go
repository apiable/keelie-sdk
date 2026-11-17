package keelie

import (
	"errors"
	"strings"
	"testing"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

func withScopes(scopes ...string) *Claims {
	return &Claims{AZP: "client", OrgID: tk.OrgID, Scopes: scopes}
}

func TestScopeMap(t *testing.T) {
	scopes, err := NewScopeMap(map[string]string{
		"GET /orders/{orderId}": "orders:read",
		"post /orders":          "orders:write",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("passes a token with the route's scope", func(t *testing.T) {
		if err := scopes.Check(withScopes("orders:read"), "get", "/orders/{orderId}"); err != nil {
			t.Fatal(err)
		}
		if err := scopes.Check(withScopes("orders:write"), "POST", "/orders"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("matches a scope and a route only to themselves", func(t *testing.T) {
		lines := captureLog(t)
		for _, c := range []struct {
			claims        *Claims
			method, route string
		}{
			{withScopes("orders"), "GET", "/orders/{orderId}"},
			{withScopes("orders:read:all"), "GET", "/orders/{orderId}"},
			{withScopes("orders:read"), "GET", "/orders/{orderId}/items"},
			{withScopes("orders:read"), "HEAD", "/orders/{orderId}"},
			{withScopes("orders:read"), "GET", "/unmapped"},
			{nil, "GET", "/orders/{orderId}"},
		} {
			err := scopes.Check(c.claims, c.method, c.route)
			var refused *InsufficientScope
			if !errors.As(err, &refused) || refused.Method != strings.ToUpper(c.method) || refused.Route != c.route {
				t.Fatalf("%s %s: %v", c.method, c.route, err)
			}
		}
		if !lines.Has("apiable.scope_refused reason=scope client=client method=GET route=/orders/{orderId}") {
			t.Fatalf("log: %q", lines.All())
		}
		// A route that is not in the map stays out of the log.
		if !lines.Has("apiable.scope_refused reason=unmapped client=client method=GET route=-") {
			t.Fatalf("log: %q", lines.All())
		}
	})
	t.Run("refuses a map that is not one scope a route", func(t *testing.T) {
		for _, routes := range []map[string]string{
			{"GET /a": "two scopes"},
			{"GET /a": ""},
			{"GET /a": "a\x1fb"},
			{"/a": "s"},
			{"GET ": "s"},
			{"GET /a": "s", "get /a": "t"},
		} {
			if _, err := NewScopeMap(routes); err == nil {
				t.Fatalf("%v: no error", routes)
			}
		}
	})
}
