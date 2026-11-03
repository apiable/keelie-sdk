// Package nethttp is the net/http middleware of the Keelie SDK.
//
// Each middleware is a func(http.Handler) http.Handler, so it works with
// http.ServeMux, chi, gorilla/mux and any other router that takes a handler.
//
// Every guard checks a token through one core, here, and through nothing else.
// Every guard refuses a token in the same way: 401, an empty body, and
// WWW-Authenticate: Bearer error="invalid_token", resource_metadata="...". The
// answer is the same for every reason. The reason goes to your log only.
//
//   - [TokenGuard], for a REST API. It checks the token and puts the claims in
//     the request's context, where [ClaimsFrom] reads them.
//   - [ScopeGuard], on each route of a REST API. It checks the scope of the route.
//   - [MCPGuard], for a Streamable HTTP MCP server. It checks the token, the
//     scope of each tool call, and reports each tool call.
//   - [AICatalog], which serves your AI Catalog with no token.
//
// Each guard also serves the RFC 9728 metadata at metadata.Path(), with no
// token, and refuses a request with no token with 401 and
// WWW-Authenticate: Bearer resource_metadata="...", so an agent can find your
// issuer. Paths outside the resource and a CORS preflight (OPTIONS) pass
// untouched.
package nethttp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	keelie "github.com/apiable/keelie-sdk/go"
)

type claimsKey struct{}

// ClaimsFrom gives the claims of the request's token, set by [TokenGuard] or
// [MCPGuard], and false when the request carries none: a path outside the
// resource, a CORS preflight, or a route with no guard before it.
func ClaimsFrom(r *http.Request) (*keelie.Claims, bool) {
	claims, ok := r.Context().Value(claimsKey{}).(*keelie.Claims)
	return claims, ok && claims != nil
}

// WithClaims is a copy of ctx that carries claims, as a guard leaves it. It is
// for a test of your own handler.
func WithClaims(ctx context.Context, claims *keelie.Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// TokenGuard is the REST middleware: it checks the token, and gives the claims
// to your routes.
//
//	guard, err := nethttp.TokenGuard(verifier, metadata)
//	http.ListenAndServe(":3000", guard(mux))
//
// A route reads the claims with [ClaimsFrom].
//
// It does not check the scope. Middleware around the router runs before the
// router picks a route, so it cannot see the route's template. Put
// [ScopeGuard] on each route, or call ScopeMap.Check in it. A route without
// either is authenticated, but it has no scope check.
//
// The verifier's audience must be the resource of the metadata, or it is an error.
func TokenGuard(verifier *keelie.TokenVerifier, metadata *keelie.ProtectedResourceMetadata) (func(http.Handler) http.Handler, error) {
	return guard(verifier, metadata, func(claims *keelie.Claims, w http.ResponseWriter, r *http.Request, next http.Handler) {
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

// RouteFunc gives the method and the template of the route a request matched,
// as written in the scope map. A template of "" is in no map.
type RouteFunc func(r *http.Request) (method, template string)

// ServeMuxRoute reads the route of http.ServeMux from r.Pattern. A pattern
// with a method, such as "GET /v1/orders/{orderId}", is the route as it is,
// also for the HEAD request that ServeMux sends to a GET pattern. A pattern with
// no method, such as "/v1/orders/{orderId}", takes the method of the request.
func ServeMuxRoute(r *http.Request) (method, template string) {
	pattern := r.Pattern
	if pattern == "" {
		return r.Method, ""
	}
	at := strings.IndexAny(pattern, " \t")
	if at < 0 {
		return r.Method, pattern
	}
	return pattern[:at], strings.TrimLeft(pattern[at:], " \t")
}

// ScopeGuard checks the scope of the http.ServeMux route it is on, against
// scopes. Its key in the map is the pattern you registered:
//
//	scopes, _ := keelie.NewScopeMap(map[string]string{"GET /v1/orders/{orderId}": "orders:read"})
//	scope := nethttp.ScopeGuard(scopes, metadata)
//	mux.Handle("GET /v1/orders/{orderId}", scope(http.HandlerFunc(getOrder)))
//
// A token that lacks the scope gets 403,
// WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="..."
// and an empty body.
//
// [TokenGuard] must run first. Without its claims, the request fails with 500,
// so that the mistake is seen. For another router, use [ScopeGuardFor].
func ScopeGuard(scopes *keelie.ScopeMap, metadata *keelie.ProtectedResourceMetadata) func(http.Handler) http.Handler {
	return ScopeGuardFor(scopes, metadata, ServeMuxRoute)
}

// ScopeGuardFor is [ScopeGuard] for any router: route reads the template the
// router matched. With chi, put it on each route with r.With, where chi has
// matched the whole pattern:
//
//	chiRoute := func(r *http.Request) (string, string) {
//		return r.Method, chi.RouteContext(r.Context()).RoutePattern()
//	}
//	router.With(nethttp.ScopeGuardFor(scopes, metadata, chiRoute)).Get("/v1/orders/{orderId}", getOrder)
func ScopeGuardFor(scopes *keelie.ScopeMap, metadata *keelie.ProtectedResourceMetadata, route RouteFunc) func(http.Handler) http.Handler {
	refusal := metadata.Challenge("insufficient_scope")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r)
			if !ok {
				http.Error(w, "keelie: ScopeGuard needs TokenGuard to run before it", http.StatusInternalServerError)
				return
			}
			method, template := route(r)
			if template == "" {
				// A route with no template is in no map.
				template = "\x00"
			}
			if scopes.Check(claims, method, template) != nil {
				respond(w, r, http.StatusForbidden, http.Header{"Www-Authenticate": {refusal}}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AICatalog serves your AI Catalog at /.well-known/ard.json and
// /.well-known/ai-catalog.json, with no token. Other requests pass untouched.
//
//	handler = nethttp.AICatalog(keelie.NewAICatalog(client, metadata, nil))(handler)
//
// The order beside the token guards does not matter: once the catalog is made
// with the metadata, the guards let a GET or a HEAD of its two paths pass.
func AICatalog(catalog *keelie.AICatalog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.EscapedPath()
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			answer, ok := catalog.Answer(r.Context(), p)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			respond(w, r, answer.Status, answer.Header, answer.Body)
		})
	}
}

type handleFunc func(claims *keelie.Claims, w http.ResponseWriter, r *http.Request, next http.Handler)

// guard is the part every guard shares. A guard adds only what it does with the claims.
//
// The verifier's audience must be the resource of the metadata, or the guard
// does not start. An agent asks keelie for a token with that resource (RFC
// 8707), and keelie writes your org's resource into aud. A verifier for another
// audience would refuse every such token, or accept a token for another server.
// Set your org's resource in keelie to the same value.
func guard(verifier *keelie.TokenVerifier, metadata *keelie.ProtectedResourceMetadata, handle handleFunc) (func(http.Handler) http.Handler, error) {
	if verifier.Audience() != metadata.Resource() {
		return nil, fmt.Errorf("keelie: the verifier's audience %q is not the resource %q: give both the same value",
			verifier.Audience(), metadata.Resource())
	}
	challenge := metadata.Challenge("")
	refusal := metadata.Challenge("invalid_token")
	document := metadata.Document()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.EscapedPath() == metadata.Path() && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				// Before the token check: with a resource at the root, the
				// metadata is under it, and the agent reads it with no token.
				respond(w, r, http.StatusOK, http.Header{"Content-Type": {"application/json"}}, document)
				return
			}
			if !guarded(r, metadata) {
				next.ServeHTTP(w, r)
				return
			}
			token, ok := keelie.BearerToken(r.Header.Get("Authorization"))
			if !ok {
				respond(w, r, http.StatusUnauthorized, http.Header{"Www-Authenticate": {challenge}}, nil)
				return
			}
			claims, err := verifier.Verify(r.Context(), token)
			if err != nil {
				respond(w, r, http.StatusUnauthorized, http.Header{"Www-Authenticate": {refusal}}, nil)
				return
			}
			handle(claims, w, r, next)
		})
	}, nil
}

// guarded is true for a request under the resource that must carry a token.
//
// A CORS preflight (OPTIONS) and every path outside the resource pass. So does
// a GET or a HEAD of the metadata, and of the AI Catalog at either of its paths
// when the catalog serves it, each compared exactly, as sent. Any other method
// on those paths needs a token.
//
// The path is compared in every form a router could route it by: as sent, as
// read (with its escapes read), with its dot segments resolved and its doubled
// slashes folded, with its escapes read once more, and without case. A request
// that is under the resource in any of these forms is guarded. It can only
// guard more than the router serves, never less.
func guarded(r *http.Request, metadata *keelie.ProtectedResourceMetadata) bool {
	if r.Method == http.MethodOptions {
		return false
	}
	sent := r.URL.EscapedPath()
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if _, catalog := keelie.CatalogMediaType(sent); sent == metadata.Path() || (catalog && metadata.ServesAICatalog()) {
			return false
		}
	}
	prefix := strings.ToLower(metadata.ResourcePath())
	if prefix == "" {
		return true
	}
	for _, form := range pathForms(r) {
		lower := strings.ToLower(form)
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			return true
		}
	}
	return false
}

func pathForms(r *http.Request) []string {
	forms := []string{r.URL.Path, r.URL.EscapedPath()}
	for _, form := range forms[:2] {
		if once, err := url.PathUnescape(form); err == nil {
			forms = append(forms, once)
		}
	}
	for _, form := range forms {
		if form != "" {
			// path.Clean resolves dot segments and folds doubled slashes, as
			// http.ServeMux does before it redirects.
			forms = append(forms, path.Clean("/"+form))
		}
	}
	return forms
}

// respond writes a whole answer. A HEAD request gets the headers only.
func respond(w http.ResponseWriter, r *http.Request, status int, header http.Header, body []byte) {
	h := w.Header()
	for name, values := range header {
		h[name] = values
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead && len(body) > 0 {
		_, _ = w.Write(body)
	}
}
