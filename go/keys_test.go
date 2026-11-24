package keelie

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

const discovery = tk.Issuer + "/.well-known/openid-configuration"

func newKeys(issuer *tk.FakeIssuer, clock *tk.Clock) *SigningKeys {
	return NewSigningKeys(tk.Issuer+"/", &SigningKeysOptions{HTTPClient: issuer.Client(), Clock: clock.Now})
}

func mustKey(t *testing.T, keys *SigningKeys, kid string) {
	t.Helper()
	if _, err := keys.Key(context.Background(), kid); err != nil {
		t.Fatalf("%s: %v", kid, err)
	}
}

func keyFails(t *testing.T, keys *SigningKeys, kid string, want error) {
	t.Helper()
	if _, err := keys.Key(context.Background(), kid); !errors.Is(err, want) {
		t.Fatalf("%s: want %v, got %v", kid, want, err)
	}
}

func TestKeysAreFetchedOnceForEveryCallerThatFindsThemCold(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	keys := newKeys(issuer, tk.NewClock())
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := keys.Key(context.Background(), "key-1"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if seen := issuer.Seen(); !slices.Equal(seen, []string{discovery, tk.JWKSURI}) {
		t.Fatalf("requests %v", seen)
	}
	if keys.Status() != StatusConnected {
		t.Fatalf("status %s", keys.Status())
	}
}

func TestAnUnknownKidIsFetchedOnceAMinuteAtMost(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	clock := tk.NewClock()
	keys := newKeys(issuer, clock)
	mustKey(t, keys, "key-1")
	keyFails(t, keys, "made-up-1", ErrUnknownKey)
	issuer.Seen()
	clock.Advance(30 * time.Second)
	keyFails(t, keys, "made-up-2", ErrUnknownKey)
	keyFails(t, keys, "made-up-3", ErrUnknownKey)
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("requests %v", seen)
	}
	clock.Advance(31 * time.Second)
	keyFails(t, keys, "made-up-4", ErrUnknownKey)
	// The jwks_uri is kept: no second discovery.
	if seen := issuer.Seen(); !slices.Equal(seen, []string{tk.JWKSURI}) {
		t.Fatalf("requests %v", seen)
	}
}

func TestARotatedKeyIsPickedUpOnItsFirstToken(t *testing.T) {
	first, next := tk.NewKeyPair("key-1", 0), tk.NewKeyPair("key-2", 1)
	issuer := tk.NewFakeIssuer(first)
	clock := tk.NewClock()
	keys := newKeys(issuer, clock)
	mustKey(t, keys, "key-1")
	issuer.Set(func(f *tk.FakeIssuer) { f.Keys = []any{first.JWK, next.JWK} })
	clock.Advance(60 * time.Second)
	mustKey(t, keys, "key-2")
	mustKey(t, keys, "key-1")
}

func TestADiscoveryDocumentOfAnotherIssuerIsRefused(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	issuer.DiscoveryIssuer = "https://issuer.example.com/realms/other"
	keys := newKeys(issuer, tk.NewClock())
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if seen := issuer.Seen(); !slices.Equal(seen, []string{discovery}) {
		t.Fatalf("requests %v", seen)
	}
	if keys.Status() != StatusOffline {
		t.Fatalf("status %s", keys.Status())
	}
}

func TestATrailingSlashOnEitherSideIsTheSameIssuer(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	issuer.DiscoveryIssuer = tk.Issuer + "/"
	keys := NewSigningKeys(tk.Issuer, &SigningKeysOptions{HTTPClient: issuer.Client()})
	mustKey(t, keys, "key-1")
}

func TestAColdFailureIsKeptForFiveSecondsThenTheNextCallerTriesAgain(t *testing.T) {
	lines := captureLog(t)
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	issuer.Down = true
	clock := tk.NewClock()
	keys := newKeys(issuer, clock)
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if seen := issuer.Seen(); !slices.Equal(seen, []string{discovery}) {
		t.Fatalf("requests %v", seen)
	}
	issuer.Set(func(f *tk.FakeIssuer) { f.Down = false })
	// Inside the window: refused at once, and the issuer is not asked.
	clock.Advance(ColdRetryInterval - time.Millisecond)
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("requests in the window %v", seen)
	}
	// Each refusal in the window logs as an ordinary one does.
	if got := lines.All(); !slices.Equal(got, []string{"apiable.keys_unavailable error=network", "apiable.keys_unavailable error=network"}) {
		t.Fatalf("lines %q", got)
	}
	// After it: the next caller fetches again.
	clock.Advance(time.Millisecond)
	mustKey(t, keys, "key-1")
	if keys.Status() != StatusConnected {
		t.Fatalf("status %s", keys.Status())
	}
}

func TestConcurrentCallersAgainstAHangingIssuerShareOneFetchAndOneTimeout(t *testing.T) {
	lines := captureLog(t)
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	issuer.Delay = time.Hour // the issuer never answers
	clock := tk.NewClock()
	keys := newKeys(issuer, clock)
	keys.timeout = 200 * time.Millisecond
	start := time.Now()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A request context with no deadline, as net/http gives it.
			if _, err := keys.Key(context.Background(), "key-1"); !errors.Is(err, ErrKeysUnavailable) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %s: more than one timeout", took)
	}
	if seen := issuer.Seen(); !slices.Equal(seen, []string{discovery}) {
		t.Fatalf("one fetch for them all, got %v", seen)
	}
	if !lines.Has("apiable.keys_unavailable error=timeout") {
		t.Fatalf("lines %q", lines.All())
	}
	// A caller after them, inside the window, does not wait again.
	start = time.Now()
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Fatalf("waited %s inside the window", took)
	}
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("requests %v", seen)
	}
}

// The deadline holds the whole request: an issuer that sends its headers, then
// a body that never ends, still fails within one timeout.
func TestAKeySetBodyThatNeverEndsFailsWithinOneTimeout(t *testing.T) {
	lines := captureLog(t)
	release := make(chan struct{})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"issuer":"`+server.URL+`","jwks_uri":"`+server.URL+`/certs"}`)
			return
		}
		_, _ = io.WriteString(w, `{"keys":[`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)
	keys := NewSigningKeys(server.URL, nil)
	keys.timeout = 200 * time.Millisecond
	start := time.Now()
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %s", took)
	}
	if !lines.Has("apiable.keys_unavailable error=timeout") {
		t.Fatalf("lines %q", lines.All())
	}
}

func TestAnEmptyKeySetDoesNotReplaceTheKeysInHand(t *testing.T) {
	lines := captureLog(t)
	pair := tk.NewKeyPair("key-1", 0)
	issuer := tk.NewFakeIssuer(pair)
	clock := tk.NewClock()
	keys := newKeys(issuer, clock)
	mustKey(t, keys, "key-1")
	for _, empty := range [][]any{{}, {map[string]any{"kty": "EC", "kid": "ec"}}} {
		issuer.Set(func(f *tk.FakeIssuer) { f.Keys = empty })
		clock.Advance(RefreshInterval)
		keyFails(t, keys, "key-2", ErrUnknownKey) // a refresh, which finds no usable key
		mustKey(t, keys, "key-1")
		if keys.Status() != StatusDegraded {
			t.Fatalf("status %s", keys.Status())
		}
	}
	if !lines.Has("apiable.keys_not_refreshed error=no_keys") {
		t.Fatalf("lines %q", lines.All())
	}
	// A valid token still verifies.
	v, err := NewTokenVerifier(tk.Issuer, tk.Resource, tk.OrgID, &TokenVerifierOptions{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), pair.Sign(nil, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestAnEmptyKeySetOnAColdStartIsAFailure(t *testing.T) {
	issuer := tk.NewFakeIssuer()
	issuer.Keys = []any{}
	keys := newKeys(issuer, tk.NewClock())
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if keys.Status() != StatusOffline {
		t.Fatalf("status %s", keys.Status())
	}
}

func TestKeysAreFetchedOverHTTPSOnlyOrFromALoopbackHost(t *testing.T) {
	lines := captureLog(t)
	// An issuer over plain http: no request is sent.
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	keys := NewSigningKeys("http://issuer.example.com/realms/portal-labs", &SigningKeysOptions{HTTPClient: issuer.Client()})
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("requests %v", seen)
	}
	if !lines.Has("apiable.keys_unavailable error=issuer_not_https") {
		t.Fatalf("lines %q", lines.All())
	}
	// A jwks_uri over plain http, from an https issuer: the key set is not fetched.
	for _, uri := range []string{"http://issuer.example.com/certs", "ftp://issuer.example.com/certs", "/certs"} {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() == discovery {
				return tk.JSON(200, map[string]any{"issuer": tk.Issuer, "jwks_uri": uri}), nil
			}
			t.Errorf("%s: a request to %s", uri, r.URL)
			return tk.JSON(404, map[string]any{}), nil
		})}
		keys := NewSigningKeys(tk.Issuer, &SigningKeysOptions{HTTPClient: client})
		keyFails(t, keys, "key-1", ErrKeysUnavailable)
	}
	if !lines.Has("apiable.keys_unavailable error=jwks_uri_not_https") {
		t.Fatalf("lines %q", lines.All())
	}
}

func TestSecureURLAllowsPlainHTTPForALoopbackHostOnly(t *testing.T) {
	for _, good := range []string{
		"https://issuer.example.com/realms/x", "HTTPS://issuer.example.com",
		"http://localhost:8080/realms/x", "http://127.0.0.1:9000", "http://[::1]:8080/x",
		"http://LOCALHOST:8080", "HTTP://LocalHost",
	} {
		if err := secureURL("url", good); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{
		"http://issuer.example.com", "http://127.0.0.2", "http://localhost.example.com",
		"http://10.0.0.1", "ftp://issuer.example.com", "https://", "issuer.example.com", "", "https:issuer",
		"https://user@issuer.example.com", "https://user:pass@issuer.example.com", "http://user@localhost",
	} {
		if err := secureURL("url", bad); err == nil {
			t.Errorf("%s was allowed", bad)
		}
	}
}

func TestCallersWaitingOnAColdFetchThatFailsShareItsFailure(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	issuer.Down = true
	keys := newKeys(issuer, tk.NewClock())
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := keys.Key(context.Background(), "key-1"); !errors.Is(err, ErrKeysUnavailable) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if seen := issuer.Seen(); len(seen) > 2 {
		t.Fatalf("one fetch for them all, got %v", seen)
	}
}

func TestTheKeysInHandGoOnVerifyingWhenARefreshFails(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	clock := tk.NewClock()
	keys := newKeys(issuer, clock)
	mustKey(t, keys, "key-1")
	issuer.Set(func(f *tk.FakeIssuer) { f.Down = true })
	clock.Advance(60 * time.Second)
	keyFails(t, keys, "key-2", ErrUnknownKey)
	if keys.Status() != StatusDegraded {
		t.Fatalf("status %s", keys.Status())
	}
	mustKey(t, keys, "key-1")
	// A failed fetch also waits an interval before the next.
	issuer.Seen()
	keyFails(t, keys, "key-3", ErrUnknownKey)
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("requests %v", seen)
	}
	issuer.Set(func(f *tk.FakeIssuer) { f.Down = false })
	clock.Advance(60 * time.Second)
	keyFails(t, keys, "key-4", ErrUnknownKey)
	if keys.Status() != StatusConnected {
		t.Fatalf("status %s", keys.Status())
	}
}

func TestOnlyRSASigningKeysForRS256AreLoadedAndOnlyTheirPublicPart(t *testing.T) {
	pair, other := tk.NewKeyPair("key-1", 0), tk.NewKeyPair("key-2", 1)
	small := tk.SmallKeyPair("small", 1024)
	issuer := tk.NewFakeIssuer()
	issuer.Keys = []any{
		other.WithKid("enc", map[string]any{"use": "enc"}),
		other.WithKid("ps", map[string]any{"alg": "PS256"}),
		map[string]any{"kty": "EC", "kid": "ec", "crv": "P-256", "x": "x", "y": "y"},
		map[string]any{"kty": "RSA", "kid": "broken", "n": "!", "e": "AQAB"},
		other.WithKid("even-e", map[string]any{"e": "AgA"}),
		other.WithKid("no-kid", map[string]any{"kid": nil}),
		small.JWK,
		other.WithKid("no-use", map[string]any{"use": nil, "alg": nil}),
		other.WithKid("null-use", map[string]any{"use": nil}),
		pair.WithKid("key-1", map[string]any{"d": "a private member, published by mistake"}),
		"not a key",
	}
	issuer.Keys[8].(map[string]any)["use"] = nil // a JSON null
	keys := newKeys(issuer, tk.NewClock())
	mustKey(t, keys, "key-1")
	mustKey(t, keys, "no-use")
	mustKey(t, keys, "null-use")
	for _, kid := range []string{"enc", "ps", "ec", "broken", "even-e", "small"} {
		keyFails(t, keys, kid, ErrUnknownKey)
	}
}

func TestAKeySetThatIsNotAListLoadsNothing(t *testing.T) {
	issuer := tk.NewFakeIssuer()
	issuer.Keys = nil
	keys := newKeys(issuer, tk.NewClock())
	keyFails(t, keys, "key-1", ErrKeysUnavailable) // "keys": null
}

func TestKeysAreOfflineUntilTheFirstToken(t *testing.T) {
	keys := newKeys(tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0)), tk.NewClock())
	if keys.Status() != StatusOffline {
		t.Fatalf("status %s", keys.Status())
	}
}
