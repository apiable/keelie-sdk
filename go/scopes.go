package keelie

// Check the scope of a verified token against the route it calls.
//
// You give the SDK one map: for each route, the scope a token must carry. A
// route is the HTTP method and the path template your router matched, such as
// "GET /orders/{orderId}". Give the template, not the path of the request, so
// that one entry covers every order.
//
// The check is strict:
//
//   - A scope matches only itself. orders:read does not grant orders, and
//     orders does not grant orders:read.
//   - A route matches only itself. There is no prefix and no wildcard.
//   - A route that is not in the map is refused. Add every route that a token
//     may call.
//
// Every refusal is an [*InsufficientScope]. Answer it with 403, not 401: the
// token is good, it does not allow this call.

import (
	"fmt"
	"strings"

	"github.com/apiable/keelie-sdk/go/internal/logx"
)

// InsufficientScope is the error of a token that does not carry the scope the
// route requires, or of a route that is not in the map.
type InsufficientScope struct {
	Method string
	Route  string
}

func (e *InsufficientScope) Error() string {
	return "keelie: insufficient scope for " + e.Method + " " + e.Route
}

// ScopeMap is the scope that each route requires. It is safe for concurrent use.
type ScopeMap struct {
	routes map[string]string
}

// NewScopeMap makes the map. routes maps each "METHOD /template" to its one
// scope, such as {"GET /orders/{orderId}": "orders:read"}. The method and the
// template are split at the first space; the method is read without case.
//
// It is an error when a key is not a method and a template, a value is not
// exactly one scope, or a route is given twice.
func NewScopeMap(routes map[string]string) (*ScopeMap, error) {
	m := &ScopeMap{routes: make(map[string]string, len(routes))}
	for entry, scope := range routes {
		at := strings.IndexByte(entry, ' ')
		if at <= 0 || at == len(entry)-1 {
			return nil, fmt.Errorf(`keelie: not "METHOD /route": %q`, entry)
		}
		method, route := entry[:at], entry[at+1:]
		if !isOneScope(scope) {
			return nil, fmt.Errorf("keelie: not one scope: %q for %s %s", scope, method, route)
		}
		k := scopeKey(method, route)
		if _, ok := m.routes[k]; ok {
			return nil, fmt.Errorf("keelie: route given twice: %s %s", method, route)
		}
		m.routes[k] = scope
	}
	return m, nil
}

// Check returns nil if the token may call the route, else an [*InsufficientScope].
// A nil claims carries no scope.
func (m *ScopeMap) Check(claims *Claims, method, route string) error {
	upper := strings.ToUpper(method)
	required, mapped := m.routes[scopeKey(upper, route)]
	if mapped && claims != nil && claims.HasScope(required) {
		return nil
	}
	reason, logged, client := "scope", route, "-"
	if !mapped {
		// A route that is not in the map can come from the request, such as an
		// MCP tool name, and stays out of the log.
		reason, logged = "unmapped", "-"
	}
	if claims != nil {
		client = claims.AZP
	}
	logx.Info("apiable.scope_refused", "reason", reason, "client", client, "method", upper, "route", logged)
	return &InsufficientScope{Method: upper, Route: route}
}

func scopeKey(method, route string) string {
	return strings.ToUpper(method) + "\x00" + route
}

// isOneScope is true for one scope, by the rule that splits the token's scope claim.
func isOneScope(scope string) bool {
	fields := pyFields(scope)
	return len(fields) == 1 && fields[0] == scope
}
