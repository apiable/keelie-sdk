package keelie

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

// A KeelieClient that misbehaves in turn: it panics, then answers nothing and no
// error, then answers with no body, then answers 202.
type badKeelie struct {
	calls atomic.Int32
}

func (b *badKeelie) Send(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
	switch b.calls.Add(1) {
	case 1:
		panic("a client bug")
	case 2:
		return nil, nil
	case 3:
		return &http.Response{StatusCode: 500}, nil
	}
	return tk.JSON(202, map[string]any{}), nil
}

func TestAKeelieClientThatPanicsOrAnswersNothingDoesNotStopTheReporter(t *testing.T) {
	lines := captureLog(t)
	k := &badKeelie{}
	r := newReporter(t, k, &UsageReporterOptions{BatchSize: 1, FlushInterval: 10 * time.Millisecond})
	r.Record(Event{ClientID: "c", CapabilityKey: "GET /x"})
	until(t, func() bool { return k.calls.Load() >= 4 })
	r.Close(context.Background())
	for _, want := range []string{
		"apiable.usage_not_sent events=1 error=client_panic",
		"apiable.usage_not_sent events=1 error=no_response",
		"apiable.usage_not_sent events=1 status=500",
		"apiable.usage_sent events=1",
	} {
		if !lines.Has(want) {
			t.Fatalf("no line %q in %q", want, lines.All())
		}
	}
	if k.calls.Load() != 4 {
		t.Fatalf("calls %d", k.calls.Load())
	}
}

func TestCloseSurvivesAKeelieClientThatPanics(t *testing.T) {
	lines := captureLog(t)
	r := newReporter(t, KeelieFunc(func(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
		panic("a client bug")
	}), nil)
	r.Record(Event{ClientID: "c", CapabilityKey: "GET /x"})
	r.Close(context.Background())
	if !lines.Has("apiable.usage_dropped events=1 reason=closed") {
		t.Fatalf("lines %q", lines.All())
	}
}

func TestACatalogClientThatPanicsOrAnswersNothingIsA503(t *testing.T) {
	for name, send := range map[string]KeelieFunc{
		"panic":       func(context.Context, string, string, http.Header, []byte) (*http.Response, error) { panic("bug") },
		"no response": func(context.Context, string, string, http.Header, []byte) (*http.Response, error) { return nil, nil },
		"too large": func(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
			return tk.Response(200, bytes.Repeat([]byte(" "), maxResponseBytes+1)), nil
		},
	} {
		metadata, _ := NewProtectedResourceMetadata(tk.Resource, tk.Issuer, nil)
		a, _ := NewAICatalog(send, metadata, nil).Answer(context.Background(), ARDPath)
		if a.Status != http.StatusServiceUnavailable {
			t.Fatalf("%s: %d", name, a.Status)
		}
	}
	// A body of the limit exactly is read.
	metadata, _ := NewProtectedResourceMetadata(tk.Resource, tk.Issuer, nil)
	full := KeelieFunc(func(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
		return tk.Response(200, bytes.Repeat([]byte(" "), maxResponseBytes)), nil
	})
	if a, _ := NewAICatalog(full, metadata, nil).Answer(context.Background(), ARDPath); a.Status != 200 || len(a.Body) != maxResponseBytes {
		t.Fatalf("%d, %d bytes", a.Status, len(a.Body))
	}
}

func TestAKeySetClientThatPanicsIsACachedNothingFailure(t *testing.T) {
	lines := captureLog(t)
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	var panicked atomic.Bool
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if !panicked.Swap(true) {
			panic("a transport bug")
		}
		return issuer.RoundTrip(r)
	})}
	keys := NewSigningKeys(tk.Issuer, &SigningKeysOptions{HTTPClient: client, Clock: tk.NewClock().Now})
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if !lines.Has("apiable.keys_unavailable error=client_panic") {
		t.Fatalf("lines %q", lines.All())
	}
	mustKey(t, keys, "key-1")
}

func TestAKeySetOverOneMiBIsRefused(t *testing.T) {
	lines := captureLog(t)
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == tk.JWKSURI {
			// A valid key set, padded past the limit.
			resp, _ := issuer.RoundTrip(r)
			body, _ := io.ReadAll(resp.Body)
			return tk.Response(200, append(body, bytes.Repeat([]byte(" "), maxResponseBytes)...)), nil
		}
		return issuer.RoundTrip(r)
	})}
	keys := NewSigningKeys(tk.Issuer, &SigningKeysOptions{HTTPClient: client, Clock: tk.NewClock().Now})
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	if !lines.Has("apiable.keys_unavailable error=too_large") {
		t.Fatalf("lines %q", lines.All())
	}
}

func credentialWith(t *testing.T, client *http.Client, tokenURL string) *SDKCredential {
	t.Helper()
	c, err := NewSDKCredential(SDKCredentialOptions{
		KeelieURL: "https://keelie.example", TokenURL: tokenURL,
		ClientID: "sdk", ClientSecret: "s3cret", HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheSDKCredentialSurvivesAClientThatPanicsAndATokenOverOneMiB(t *testing.T) {
	var mode atomic.Int32
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		switch mode.Load() {
		case 0:
			panic("a transport bug")
		case 1:
			return tk.Response(200, append([]byte(`{"access_token":"t","expires_in":300}`), bytes.Repeat([]byte(" "), maxResponseBytes)...)), nil
		}
		if r.URL.Path == "/token" {
			return tk.JSON(200, map[string]any{"access_token": "t", "expires_in": 300}), nil
		}
		return tk.JSON(200, map[string]any{}), nil
	})}
	c := credentialWith(t, client, "https://issuer.example.com/token")
	if _, err := c.Send(context.Background(), http.MethodGet, "/ai-catalog", nil, nil); !errors.Is(err, errClientPanic) {
		t.Fatalf("a panic: %v", err)
	}
	mode.Store(1)
	if _, err := c.Send(context.Background(), http.MethodGet, "/ai-catalog", nil, nil); !errors.Is(err, errTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	mode.Store(2)
	resp, err := c.Send(context.Background(), http.MethodGet, "/ai-catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestTheTokenRequestFollowsNoRedirectEvenWithAClientThatWould(t *testing.T) {
	var mu sync.Mutex
	var elsewhere []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		elsewhere = append(elsewhere, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"t","expires_in":300}`)
	}))
	defer other.Close()
	for _, status := range []int{307, 308} {
		issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/token", status)
		}))
		// The caller's own client follows redirects, as http.Client does by default.
		client := &http.Client{}
		c := credentialWith(t, client, issuer.URL+"/token")
		_, err := c.Send(context.Background(), http.MethodGet, "/ai-catalog", nil, nil)
		issuer.Close()
		if err == nil || !strings.Contains(err.Error(), "answered "+strconv.Itoa(status)) {
			t.Fatalf("%d: %v", status, err)
		}
		if client.CheckRedirect != nil {
			t.Fatal("the caller's client was changed")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(elsewhere) != 0 {
		t.Fatalf("the secret went on to another address: %q", elsewhere)
	}
}
