package keelie

import (
	"context"
	"errors"
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

func TestAColdFailureCachesNothingSoTheNextCallerTriesAgain(t *testing.T) {
	issuer := tk.NewFakeIssuer(tk.NewKeyPair("key-1", 0))
	issuer.Down = true
	keys := newKeys(issuer, tk.NewClock())
	keyFails(t, keys, "key-1", ErrKeysUnavailable)
	issuer.Set(func(f *tk.FakeIssuer) { f.Down = false })
	mustKey(t, keys, "key-1")
	if keys.Status() != StatusConnected {
		t.Fatalf("status %s", keys.Status())
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
