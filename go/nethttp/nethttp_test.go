package nethttp_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	keelie "github.com/apiable/keelie-sdk/go"
	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
	"github.com/apiable/keelie-sdk/go/nethttp"
)

func TestMain(m *testing.M) {
	keelie.SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

var pair = tk.NewKeyPair("key-1", 0)

func verifier(t *testing.T, audience string) *keelie.TokenVerifier {
	t.Helper()
	keys := keelie.NewSigningKeys(tk.Issuer, &keelie.SigningKeysOptions{HTTPClient: tk.NewFakeIssuer(pair).Client()})
	v, err := keelie.NewTokenVerifier(tk.Issuer, audience, tk.OrgID, &keelie.TokenVerifierOptions{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func metadata(t *testing.T, resource string) *keelie.ProtectedResourceMetadata {
	t.Helper()
	m, err := keelie.NewProtectedResourceMetadata(resource, tk.Issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// must is value, and panics on err: the setup of a test cannot fail.
func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

type restAPI struct {
	handler  http.Handler
	metadata *keelie.ProtectedResourceMetadata
	reached  atomic.Int32
}

func newRESTAPI(t *testing.T) *restAPI {
	api := &restAPI{metadata: metadata(t, tk.Resource)}
	scopes := must(keelie.NewScopeMap(map[string]string{
		"GET /v1/orders/{orderId}": "orders:read",
		"POST /v1/orders":          "orders:write",
		"GET /v1/items/{itemId}":   "items:read",
		"GET /v1/any/{id}":         "orders:read",
	}))
	scope := nethttp.ScopeGuard(scopes, api.metadata)
	catalog := keelie.NewAICatalog(keelie.KeelieFunc(func(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
		return tk.JSON(200, map[string]any{"entries": []any{}}), nil
	}), api.metadata, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		_, ok := nethttp.ClaimsFrom(r)
		writeJSON(w, 200, map[string]any{"ok": true, "claims": ok})
	})
	mux.Handle("GET /v1/orders/{orderId}", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.reached.Add(1)
		claims, _ := nethttp.ClaimsFrom(r)
		writeJSON(w, 200, map[string]any{"orderId": r.PathValue("orderId"), "azp": claims.AZP})
	})))
	mux.Handle("POST /v1/orders", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.reached.Add(1)
		writeJSON(w, 201, map[string]any{})
	})))
	mux.Handle("GET /v1/unmapped", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.reached.Add(1)
		writeJSON(w, 200, map[string]any{})
	})))
	// A pattern with no method takes the method of the request.
	mux.Handle("/v1/any/{id}", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.reached.Add(1)
		writeJSON(w, 200, map[string]any{})
	})))
	// A sub-mux behind StripPrefix: its pattern is its own.
	items := http.NewServeMux()
	items.Handle("GET /items/{itemId}", scope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.reached.Add(1)
		writeJSON(w, 200, map[string]any{"item": true})
	})))
	mux.Handle("/v1/items/", http.StripPrefix("/v1", items))

	guard := must(nethttp.TokenGuard(verifier(t, tk.Resource), api.metadata))
	api.handler = nethttp.AICatalog(catalog)(guard(mux))
	return api
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// do sends one request with this raw target, as a server reads it.
func do(h http.Handler, method, target, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(extra map[string]any) string { return "Bearer " + pair.Sign(extra, nil) }

func TestTheMetadataIsServedWithNoToken(t *testing.T) {
	api := newRESTAPI(t)
	res := do(api.handler, "GET", "/.well-known/oauth-protected-resource/v1", "")
	if res.Code != 200 || res.Header().Get("Content-Type") != "application/json" || res.Body.String() != string(api.metadata.Document()) {
		t.Fatalf("%d %v %s", res.Code, res.Header(), res.Body)
	}
	head := do(api.handler, "HEAD", "/.well-known/oauth-protected-resource/v1", "")
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != res.Header().Get("Content-Length") {
		t.Fatalf("HEAD %d %v", head.Code, head.Header())
	}
}

func TestARequestWithNoTokenIsRefusedAndNamesTheMetadata(t *testing.T) {
	api := newRESTAPI(t)
	res := do(api.handler, "GET", "/v1/orders/42", "")
	if res.Code != 401 || res.Header().Get("WWW-Authenticate") != api.metadata.Challenge("") || res.Body.Len() != 0 {
		t.Fatalf("%d %v %q", res.Code, res.Header(), res.Body)
	}
	if res := do(api.handler, "GET", "/v1/orders/42", "Basic abc"); res.Code != 401 {
		t.Fatal(res.Code)
	}
}

func TestABadTokenIsRefusedTheSameWayForEveryReason(t *testing.T) {
	api := newRESTAPI(t)
	for _, auth := range []string{"Bearer nope", bearer(map[string]any{"org_id": tk.OtherOrg}), bearer(map[string]any{"exp": 1})} {
		res := do(api.handler, "GET", "/v1/orders/42", auth)
		if res.Code != 401 || res.Header().Get("WWW-Authenticate") != api.metadata.Challenge("invalid_token") || res.Body.Len() != 0 {
			t.Fatalf("%d %v", res.Code, res.Header())
		}
	}
}

func TestARouteWhoseScopeTheTokenCarriesGetsTheClaims(t *testing.T) {
	api := newRESTAPI(t)
	res := do(api.handler, "GET", "/v1/orders/42", bearer(nil))
	if res.Code != 200 || strings.TrimSpace(res.Body.String()) != `{"azp":"consumer-client","orderId":"42"}` {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	// ServeMux sends a HEAD to the GET pattern, and the GET pattern's scope applies.
	if res := do(api.handler, "HEAD", "/v1/orders/42", bearer(nil)); res.Code != 200 {
		t.Fatalf("HEAD %d", res.Code)
	}
	// A pattern with no method takes the request's method.
	if res := do(api.handler, "GET", "/v1/any/1", bearer(nil)); res.Code != 200 {
		t.Fatalf("any GET %d", res.Code)
	}
	if res := do(api.handler, "DELETE", "/v1/any/1", bearer(nil)); res.Code != 403 {
		t.Fatalf("any DELETE %d", res.Code)
	}
}

func TestARouteWhoseScopeTheTokenLacksOrThatIsNotInTheMapGets403(t *testing.T) {
	api := newRESTAPI(t)
	for _, c := range []struct{ method, path string }{{"POST", "/v1/orders"}, {"GET", "/v1/unmapped"}} {
		res := do(api.handler, c.method, c.path, bearer(nil))
		if res.Code != 403 || res.Header().Get("WWW-Authenticate") != api.metadata.Challenge("insufficient_scope") || res.Body.Len() != 0 {
			t.Fatalf("%s %s: %d %v", c.method, c.path, res.Code, res.Header())
		}
	}
	if api.reached.Load() != 0 {
		t.Fatal("a refused route ran")
	}
}

func TestTheTemplateOfASubMuxIsItsOwnPattern(t *testing.T) {
	api := newRESTAPI(t)
	// The sub-mux's pattern is "GET /items/{itemId}", which is not in the map.
	if res := do(api.handler, "GET", "/v1/items/7", bearer(map[string]any{"scope": "items:read"})); res.Code != 403 {
		t.Fatalf("%d", res.Code)
	}
}

func TestScopeGuardForReadsTheTemplateOfAnotherRouter(t *testing.T) {
	m := metadata(t, tk.Resource)
	scopes := must(keelie.NewScopeMap(map[string]string{"GET /v1/orders/{orderId}": "orders:read"}))
	route := func(r *http.Request) (string, string) { return r.Method, "/v1/orders/{orderId}" }
	guard := must(nethttp.TokenGuard(verifier(t, tk.Resource), m))
	h := guard(nethttp.ScopeGuardFor(scopes, m, route)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})))
	if res := do(h, "GET", "/v1/orders/1", bearer(nil)); res.Code != 204 {
		t.Fatal(res.Code)
	}
	if res := do(h, "GET", "/v1/orders/1", bearer(map[string]any{"scope": "other"})); res.Code != 403 {
		t.Fatal(res.Code)
	}
	empty := func(r *http.Request) (string, string) { return r.Method, "" }
	h = guard(nethttp.ScopeGuardFor(scopes, m, empty)(http.NotFoundHandler()))
	if res := do(h, "GET", "/v1/orders/1", bearer(nil)); res.Code != 403 {
		t.Fatalf("a route with no template is in no map: %d", res.Code)
	}
}

func TestPathsOutsideTheResourceAndAPreflightPassUntouched(t *testing.T) {
	api := newRESTAPI(t)
	res := do(api.handler, "GET", "/health", "")
	if res.Code != 200 || strings.TrimSpace(res.Body.String()) != `{"claims":false,"ok":true}` {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if res := do(api.handler, "OPTIONS", "/v1/orders/42", ""); res.Code == 401 {
		t.Fatal("a preflight was refused")
	}
}

func TestEveryFormOfAPathTheRouterCouldRouteIsGuarded(t *testing.T) {
	api := newRESTAPI(t)
	for _, path := range []string{
		"/V1/orders/42",
		"/v1/../v1/orders/42",
		"/v1/./orders/42",
		"/%76%31/orders/42",
		"/%2576%2531/orders/42",
		"//v1/orders/42",
		"/x/..%2fv1/orders/42",
		"/x/..%2Fv1/orders/42",
		"/v1%2forders/42",
		"/V1%2FORDERS/42",
	} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			res := do(api.handler, method, path, "")
			if res.Code != 401 {
				t.Errorf("%s %s: %d", method, path, res.Code)
			}
		}
	}
	if api.reached.Load() != 0 {
		t.Fatal("a protected handler ran without a token")
	}
}

func TestTheAICatalogIsServedWithNoToken(t *testing.T) {
	api := newRESTAPI(t)
	res := do(api.handler, "GET", "/.well-known/ai-catalog.json", "")
	if res.Code != 200 || res.Header().Get("Content-Type") != "application/ai-catalog+json" || res.Body.String() != `{"entries":[]}` {
		t.Fatalf("%d %v %s", res.Code, res.Header(), res.Body)
	}
	if res := do(api.handler, "HEAD", "/.well-known/ard.json", ""); res.Code != 200 || res.Body.Len() != 0 || res.Header().Get("Content-Length") != "14" {
		t.Fatalf("HEAD %d %v", res.Code, res.Header())
	}
}

func TestAnotherMethodOnTheMetadataOrCatalogPathNeedsAToken(t *testing.T) {
	m := metadata(t, "https://api.example.com")
	keelie.NewAICatalog(keelie.KeelieFunc(func(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
		return tk.JSON(200, map[string]any{}), nil
	}), m, nil)
	guard := must(nethttp.TokenGuard(verifier(t, "https://api.example.com"), m))
	h := guard(http.NotFoundHandler())
	for _, c := range []struct{ method, path string }{
		{"POST", "/.well-known/oauth-protected-resource"},
		{"DELETE", "/.well-known/oauth-protected-resource"},
		{"POST", "/.well-known/ard.json"},
		{"PUT", "/.well-known/ai-catalog.json"},
		// Compared as sent: an escaped form is not the catalog path.
		{"GET", "/.well-known%2Fard.json"},
		{"GET", "/.well-known/%61rd.json"},
	} {
		if res := do(h, c.method, c.path, ""); res.Code != 401 {
			t.Errorf("%s %s: %d", c.method, c.path, res.Code)
		}
	}
	// With the catalog, a GET of its path passes the guard (to the catalog, mounted in front).
	if res := do(h, "GET", "/.well-known/ard.json", ""); res.Code != 404 {
		t.Fatalf("GET ard.json: %d", res.Code)
	}
}

func TestAGuardWithNoCatalogGuardsTheCatalogPaths(t *testing.T) {
	m := metadata(t, "https://api.example.com")
	guard := must(nethttp.TokenGuard(verifier(t, "https://api.example.com"), m))
	for _, path := range []string{keelie.ARDPath, keelie.CatalogPath} {
		if res := do(guard(http.NotFoundHandler()), "GET", path, ""); res.Code != 401 {
			t.Errorf("%s: %d", path, res.Code)
		}
	}
	// A resource at the root serves its metadata with no token.
	if res := do(guard(http.NotFoundHandler()), "GET", "/.well-known/oauth-protected-resource", ""); res.Code != 200 {
		t.Fatal(res.Code)
	}
}

func TestScopeGuardWithNoTokenGuardBeforeItFails(t *testing.T) {
	m := metadata(t, tk.Resource)
	scopes := must(keelie.NewScopeMap(map[string]string{"GET /v1/orders/{orderId}": "orders:read"}))
	mux := http.NewServeMux()
	mux.Handle("GET /v1/orders/{orderId}", nethttp.ScopeGuard(scopes, m)(http.NotFoundHandler()))
	if res := do(mux, "GET", "/v1/orders/1", bearer(nil)); res.Code != 500 {
		t.Fatal(res.Code)
	}
}

func TestTheGuardsDoNotStartWhenTheVerifiersAudienceIsNotTheResource(t *testing.T) {
	v := verifier(t, "https://api.example.com/v2")
	m := metadata(t, tk.Resource)
	if _, err := nethttp.TokenGuard(v, m); err == nil {
		t.Fatal("TokenGuard started")
	}
	r := must(keelie.NewUsageReporter(keelie.KeelieFunc(nil), nil))
	if _, err := nethttp.MCPGuard(nethttp.MCPGuardOptions{Verifier: v, Metadata: m, Reporter: r}); err == nil {
		t.Fatal("MCPGuard started")
	}
}

func TestServeMuxRouteReadsThePattern(t *testing.T) {
	for pattern, want := range map[string][2]string{
		"GET /v1/orders/{orderId}":  {"GET", "/v1/orders/{orderId}"},
		"GET \t /v1/x":              {"GET", "/v1/x"},
		"/v1/orders/{orderId}":      {"PATCH", "/v1/orders/{orderId}"},
		"POST api.example.com/v1/x": {"POST", "api.example.com/v1/x"},
		"":                          {"PATCH", ""},
	} {
		r := httptest.NewRequest("PATCH", "/", nil)
		r.Pattern = pattern
		method, template := nethttp.ServeMuxRoute(r)
		if method != want[0] || template != want[1] {
			t.Errorf("%q: %q %q", pattern, method, template)
		}
	}
}

// What each Consumer holds when it calls, 20 minutes into an outage of keelie
// and its issuer. A token expired more than the 30 seconds of leeway ago is
// refused. From the SDK's view there are three cases: a live token, an
// expired token, and no token.
func TestConsumersDuringA20MinuteOutage(t *testing.T) {
	issuer := tk.NewFakeIssuer(pair)
	keys := keelie.NewSigningKeys(tk.Issuer, &keelie.SigningKeysOptions{HTTPClient: issuer.Client()})
	v := must(keelie.NewTokenVerifier(tk.Issuer, tk.Resource, tk.OrgID, &keelie.TokenVerifierOptions{Keys: keys}))
	m := metadata(t, tk.Resource)
	guard := must(nethttp.TokenGuard(v, m))
	h := guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	// Before the outage, one call loads the issuer's keys.
	if res := do(h, "GET", "/v1", bearer(nil)); res.Code != 200 {
		t.Fatal(res.Code)
	}
	issuer.Set(func(f *tk.FakeIssuer) { f.Down = true })
	now := time.Now().Unix()
	for _, c := range []struct {
		consumer string
		auth     string
		status   int
	}{
		{"large balance", bearer(map[string]any{"exp": now + 3600}), 200},
		{"balance reaches zero, token alive", bearer(map[string]any{"exp": now + 120}), 200},
		{"balance reaches zero, token expired", bearer(map[string]any{"exp": now - 31}), 401},
		{"delinquent", bearer(map[string]any{"exp": now - 600}), 401},
		{"never seen", "", 401},
	} {
		if res := do(h, "GET", "/v1", c.auth); res.Code != c.status {
			t.Errorf("%s: %d", c.consumer, res.Code)
		}
	}
	if v.Status() != keelie.StatusConnected {
		t.Fatalf("the SDK does not poll, so the status stays: %s", v.Status())
	}
}
