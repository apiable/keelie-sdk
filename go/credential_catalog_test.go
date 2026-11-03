package keelie

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTheSDKCredentialMintsOnceSendsTheTokenAndMintsAgainOnA401(t *testing.T) {
	type call struct{ url, auth, body string }
	var mu sync.Mutex
	var calls []call
	minted := 0
	refuse := false
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
		}
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call{r.URL.String(), r.Header.Get("Authorization"), body})
		if r.URL.String() == "https://issuer.example.com/token" {
			minted++
			time.Sleep(10 * time.Millisecond)
			return tk.JSON(200, map[string]any{"access_token": "token-" + string(rune('0'+minted)), "expires_in": 300}), nil
		}
		if refuse {
			refuse = false
			return tk.Response(401, nil), nil
		}
		return tk.JSON(200, map[string]any{"ok": true}), nil
	})}
	keelie, err := NewSDKCredential(SDKCredentialOptions{
		KeelieURL:    "https://keelie.example/",
		TokenURL:     "https://issuer.example.com/token",
		ClientID:     "sdk",
		ClientSecret: "s3cret&more",
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := keelie.Send(context.Background(), http.MethodGet, "/ai-catalog", nil, nil)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if minted != 1 {
		t.Fatalf("minted %d", minted)
	}
	if calls[0].body != "grant_type=client_credentials&client_id=sdk&client_secret=s3cret%26more" {
		t.Fatal(calls[0].body)
	}
	for _, c := range calls[1:] {
		if c.url != "https://keelie.example/ai-catalog" || c.auth != "Bearer token-1" {
			t.Fatalf("call %+v", c)
		}
	}
	refuse = true
	resp, err := keelie.Send(context.Background(), http.MethodPost, "/usage-events:report", http.Header{"Idempotency-Key": {"k"}}, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	last := calls[len(calls)-1]
	if resp.StatusCode != 200 || minted != 2 || last.auth != "Bearer token-2" || last.body != "{}" {
		t.Fatalf("status %d, minted %d, last %+v", resp.StatusCode, minted, last)
	}
}

func TestTheSDKCredentialFailsWhenTheTokenEndpointRefuses(t *testing.T) {
	keelie, err := NewSDKCredential(SDKCredentialOptions{
		KeelieURL: "https://keelie.example", TokenURL: "https://issuer.example.com/token",
		ClientID: "sdk", ClientSecret: "wrong",
		HTTPClient: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return tk.Response(401, nil), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keelie.Send(context.Background(), http.MethodGet, "/ai-catalog", nil, nil); err == nil {
		t.Fatal("no error")
	}
	if _, err := NewSDKCredential(SDKCredentialOptions{KeelieURL: "https://keelie.example"}); err == nil {
		t.Fatal("no error for missing options")
	}
}

const catalogDocument = `{"specVersion":"0.91","entries":[]}`

type catalogSetup struct {
	clock    *tk.Clock
	metadata *ProtectedResourceMetadata
	catalog  *AICatalog
	fetched  atomic.Int32
	mu       sync.Mutex
	answers  []int // 0 is a network error
	delay    time.Duration
}

func newCatalog(t *testing.T) *catalogSetup {
	s := &catalogSetup{clock: tk.NewClock()}
	keelie := KeelieFunc(func(_ context.Context, method, path string, _ http.Header, _ []byte) (*http.Response, error) {
		if method != http.MethodGet || path != "/ai-catalog" {
			t.Errorf("%s %s", method, path)
		}
		s.fetched.Add(1)
		s.mu.Lock()
		answer := 200
		if len(s.answers) > 0 {
			answer, s.answers = s.answers[0], s.answers[1:]
		}
		delay := s.delay
		s.mu.Unlock()
		time.Sleep(delay)
		if answer == 0 {
			return nil, errors.New("fetch failed")
		}
		if answer == 200 {
			return tk.Response(200, []byte(catalogDocument)), nil
		}
		return tk.Response(answer, nil), nil
	})
	metadata, err := NewProtectedResourceMetadata(tk.Resource, tk.Issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.metadata = metadata
	s.catalog = NewAICatalog(keelie, metadata, &AICatalogOptions{Clock: s.clock.Now})
	return s
}

func (s *catalogSetup) fail(answers ...int) {
	s.mu.Lock()
	s.answers = answers
	s.mu.Unlock()
}

func (s *catalogSetup) answer(t *testing.T, path string) *CatalogAnswer {
	t.Helper()
	a, ok := s.catalog.Answer(context.Background(), path)
	if !ok {
		t.Fatalf("%s is not a catalog path", path)
	}
	return a
}

func TestTheCatalogTellsTheGuardsThatItsPathsNeedNoToken(t *testing.T) {
	s := newCatalog(t)
	if !s.metadata.ServesAICatalog() {
		t.Fatal("the guards do not know")
	}
}

func TestTheCatalogServesOneBodyAtBothPathsAndKeepsIt60Seconds(t *testing.T) {
	s := newCatalog(t)
	ard := s.answer(t, "/.well-known/ard.json")
	ai := s.answer(t, "/.well-known/ai-catalog.json")
	if ard.Status != 200 || ard.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("ard %+v", ard)
	}
	if ai.Header.Get("Content-Type") != "application/ai-catalog+json" || ai.Header.Get("Cache-Control") != "max-age=60" {
		t.Fatalf("ai %+v", ai)
	}
	if string(ai.Body) != catalogDocument || s.fetched.Load() != 1 {
		t.Fatalf("body %s, fetched %d", ai.Body, s.fetched.Load())
	}
	s.clock.Advance(59 * time.Second)
	s.answer(t, "/.well-known/ard.json")
	if s.fetched.Load() != 1 {
		t.Fatal("fetched again inside 60 seconds")
	}
	s.clock.Advance(time.Second)
	s.answer(t, "/.well-known/ard.json")
	if s.fetched.Load() != 2 {
		t.Fatal("not fetched again after 60 seconds")
	}
	if _, ok := s.catalog.Answer(context.Background(), "/other"); ok {
		t.Fatal("/other is not a catalog path")
	}
}

func TestTheCatalogAnswers503WhenKeelieFailsNeverAnOldCopyAndAsksAgainAfter10Seconds(t *testing.T) {
	for _, failure := range []int{500, 404, 0} {
		s := newCatalog(t)
		s.answer(t, "/.well-known/ard.json")
		s.clock.Advance(60 * time.Second)
		s.fail(failure)
		down := s.answer(t, "/.well-known/ard.json")
		if down.Status != 503 || down.Header.Get("Retry-After") != "10" || down.Header.Get("Cache-Control") != "no-store" || len(down.Body) != 0 {
			t.Fatalf("%d: %+v", failure, down)
		}
		s.clock.Advance(9 * time.Second)
		if s.answer(t, "/.well-known/ard.json").Status != 503 || s.fetched.Load() != 2 {
			t.Fatalf("%d: asked again inside 10 seconds", failure)
		}
		s.clock.Advance(time.Second)
		if s.answer(t, "/.well-known/ard.json").Status != 200 || s.fetched.Load() != 3 {
			t.Fatalf("%d: not asked again after 10 seconds", failure)
		}
	}
}

func TestTheCatalogMakesOneFetchForManyRequestsAtOnce(t *testing.T) {
	s := newCatalog(t)
	s.delay = 20 * time.Millisecond
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a, _ := s.catalog.Answer(context.Background(), ARDPath); a.Status != 200 {
				t.Error(a.Status)
			}
		}()
	}
	wg.Wait()
	if s.fetched.Load() != 1 {
		t.Fatalf("fetched %d", s.fetched.Load())
	}
}
