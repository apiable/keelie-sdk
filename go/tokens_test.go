package keelie

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

func newVerifier(t *testing.T, issuer *tk.FakeIssuer) *TokenVerifier {
	t.Helper()
	keys := NewSigningKeys(tk.Issuer, &SigningKeysOptions{HTTPClient: issuer.Client()})
	v, err := NewTokenVerifier(tk.Issuer, tk.Resource, tk.OrgID, &TokenVerifierOptions{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func rejects(t *testing.T, v *TokenVerifier, token string, want Reason) {
	t.Helper()
	claims, err := v.Verify(context.Background(), token)
	var rejected *TokenRejected
	if !errors.As(err, &rejected) {
		t.Fatalf("want %s, got claims %+v and error %v", want, claims, err)
	}
	if rejected.Reason != want {
		t.Fatalf("want %s, got %s", want, rejected.Reason)
	}
}

func TestVerifyReturnsTheClaimsOfAGoodToken(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	claims, err := v.Verify(context.Background(), pair.Sign(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if claims.AZP != "consumer-client" || claims.OrgID != tk.OrgID || claims.JTI != "token-1" || claims.ConsumerID != "" {
		t.Fatalf("claims: %+v", claims)
	}
	scopes := slices.Clone(claims.Scopes)
	slices.Sort(scopes)
	if !slices.Equal(scopes, []string{"orders:read", "profile"}) {
		t.Fatalf("scopes: %v", claims.Scopes)
	}
	if !claims.ExpiresAt.After(time.Now()) || claims.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expires at %v", claims.ExpiresAt)
	}
	if !claims.HasScope("profile") || claims.HasScope("orders") {
		t.Fatal("HasScope")
	}
}

func TestVerifyReadsConsumerIDInItsCanonicalForm(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	claims, err := v.Verify(context.Background(), pair.Sign(map[string]any{"consumer_id": "{1B2C3D4E-5F60-4718-8293-A4B5C6D7E8F9}"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if claims.ConsumerID != tk.Consumer {
		t.Fatalf("consumer: %q", claims.ConsumerID)
	}
	claims, err = v.Verify(context.Background(), pair.Sign(map[string]any{"consumer_id": nil}, nil))
	if err != nil || claims.ConsumerID != "" {
		t.Fatalf("a null consumer_id is none: %v %+v", err, claims)
	}
}

func TestVerifyRefusesAnotherAlgorithmBeforeAnyKeyIsFetched(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	issuer := tk.NewFakeIssuer(pair)
	v := newVerifier(t, issuer)
	rejects(t, v, tk.Unsigned(map[string]any{"alg": "none", "kid": "key-1"}), ReasonAlgorithm)
	rejects(t, v, tk.Unsigned(map[string]any{"alg": "HS256", "kid": "key-1"}), ReasonAlgorithm)
	rejects(t, v, tk.Unsigned(map[string]any{"kid": "key-1"}), ReasonAlgorithm)
	rejects(t, v, tk.Unsigned(map[string]any{"alg": "RS256"}), ReasonKid)
	rejects(t, v, tk.Unsigned(map[string]any{"alg": "RS256", "kid": ""}), ReasonKid)
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("fetched %v", seen)
	}
}

func TestVerifyRefusesWhatDoesNotParse(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	issuer := tk.NewFakeIssuer(pair)
	v := newVerifier(t, issuer)
	good := pair.Sign(nil, nil)
	for _, token := range []string{
		"not-a-token",
		"",
		"a.b",
		good + ".x",
		good + "=", // padding
		good[:len(good)-1] + "\n" + good[len(good)-1:],                                    // a line break
		tk.Unsigned(map[string]any{"alg": "RS256", "kid": 7}),                             // kid is not a string
		tk.Unsigned(map[string]any{"alg": "RS256", "kid": "key-1", "crit": []any{"exp"}}), // an unknown critical extension
		tk.Unsigned(map[string]any{"alg": "RS256", "kid": "key-1", "b64": false}),         // a detached payload
		pair.SignRaw(`["not","an","object"]`, `{}`),
	} {
		rejects(t, v, token, ReasonMalformed)
	}
	if seen := issuer.Seen(); len(seen) != 0 {
		t.Fatalf("fetched %v", seen)
	}
	// A payload that is not an object, signed with the key, is malformed after the signature check.
	rejects(t, v, pair.SignRaw(`{"alg":"RS256","kid":"key-1"}`, `[1]`), ReasonMalformed)
	rejects(t, v, pair.SignRaw(`{"alg":"RS256","kid":"key-1"}`, `{"exp":1}{}`), ReasonMalformed)
}

func TestVerifyRefusesAnUnknownKid(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	rejects(t, v, tk.NewKeyPair("key-2", 1).Sign(nil, nil), ReasonKid)
}

func TestVerifyRefusesASignatureOfAnotherKeyWithTheSameKid(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	rejects(t, v, tk.NewKeyPair("key-1", 1).Sign(nil, nil), ReasonSignature)
}

func TestVerifyChecksTheTimes(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	now := time.Now().Unix()
	rejects(t, v, pair.Sign(map[string]any{"exp": now - 31}, nil), ReasonExpired)
	if _, err := v.Verify(context.Background(), pair.Sign(map[string]any{"exp": now - 20}, nil)); err != nil {
		t.Fatalf("inside the leeway: %v", err)
	}
	rejects(t, v, pair.Sign(map[string]any{"nbf": now + 60}, nil), ReasonNotYetValid)
	rejects(t, v, pair.Sign(map[string]any{"iat": now + 60}, nil), ReasonNotYetValid)
	rejects(t, v, pair.Sign(map[string]any{"exp": tk.Remove}, nil), ReasonClaims)
	rejects(t, v, pair.Sign(map[string]any{"exp": nil}, nil), ReasonClaims)
	rejects(t, v, pair.Sign(map[string]any{"exp": "soon"}, nil), ReasonMalformed)
	rejects(t, v, pair.Sign(map[string]any{"nbf": "soon"}, nil), ReasonMalformed)
	rejects(t, v, pair.Sign(map[string]any{"iat": []any{}}, nil), ReasonMalformed)
	// A date past what Python's datetime holds.
	rejects(t, v, pair.Sign(map[string]any{"exp": 1e15}, nil), ReasonClaims)
	if _, err := v.Verify(context.Background(), pair.Sign(map[string]any{"exp": float64(now) + 60.5, "nbf": now - 10}, nil)); err != nil {
		t.Fatalf("a fractional exp: %v", err)
	}
}

func TestVerifyChecksTheIssuerAndTheAudience(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	rejects(t, v, pair.Sign(map[string]any{"iss": "https://issuer.example.com/realms/other"}, nil), ReasonIssuer)
	rejects(t, v, pair.Sign(map[string]any{"iss": 7}, nil), ReasonIssuer)
	rejects(t, v, pair.Sign(map[string]any{"iss": tk.Remove}, nil), ReasonClaims)
	rejects(t, v, pair.Sign(map[string]any{"aud": "https://api.example.com/v2"}, nil), ReasonAudience)
	rejects(t, v, pair.Sign(map[string]any{"aud": tk.Remove}, nil), ReasonAudience)
	rejects(t, v, pair.Sign(map[string]any{"aud": ""}, nil), ReasonAudience)
	rejects(t, v, pair.Sign(map[string]any{"aud": []any{tk.Resource, 7}}, nil), ReasonAudience)
	if _, err := v.Verify(context.Background(), pair.Sign(map[string]any{"aud": []any{"https://other.example.com", tk.Resource}}, nil)); err != nil {
		t.Fatalf("aud as a list: %v", err)
	}
}

func TestVerifyChecksTheClaimsKeelieWrites(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	for _, c := range []struct {
		claims map[string]any
		reason Reason
	}{
		{map[string]any{"org_id": tk.OtherOrg}, ReasonOrg},
		{map[string]any{"org_id": "nope"}, ReasonClaims},
		{map[string]any{"org_id": tk.Remove}, ReasonClaims},
		{map[string]any{"org_id": 12}, ReasonClaims},
		{map[string]any{"azp": tk.Remove}, ReasonClaims},
		{map[string]any{"azp": ""}, ReasonClaims},
		{map[string]any{"scope": []any{"orders:read"}}, ReasonClaims},
		{map[string]any{"scope": nil}, ReasonClaims},
		// PyJWT itself refuses a jti or a sub that is not a string.
		{map[string]any{"jti": 7}, ReasonMalformed},
		{map[string]any{"jti": nil}, ReasonMalformed},
		{map[string]any{"sub": 7}, ReasonMalformed},
		{map[string]any{"typ": "ID"}, ReasonTyp},
		{map[string]any{"typ": tk.Remove}, ReasonTyp},
		{map[string]any{"consumer_id": "nope"}, ReasonClaims},
		{map[string]any{"consumer_id": 12}, ReasonClaims},
		// typ is checked before consumer_id, as in Python.
		{map[string]any{"typ": "ID", "consumer_id": "nope"}, ReasonTyp},
	} {
		rejects(t, v, pair.Sign(c.claims, nil), c.reason)
	}
}

func TestVerifyReadsAMissingScopeAsNoScope(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	v := newVerifier(t, tk.NewFakeIssuer(pair))
	claims, err := v.Verify(context.Background(), pair.Sign(map[string]any{"scope": tk.Remove, "jti": tk.Remove}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Scopes) != 0 || claims.JTI != "" {
		t.Fatalf("claims: %+v", claims)
	}
	claims, err = v.Verify(context.Background(), pair.Sign(map[string]any{"scope": " a\tb  a\x1fc "}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(claims.Scopes, []string{"a", "b", "c"}) {
		t.Fatalf("scopes split as Python splits them: %q", claims.Scopes)
	}
}

func TestVerifyRefusesEveryTokenWhileTheIssuerCannotBeReached(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	issuer := tk.NewFakeIssuer(pair)
	issuer.Down = true
	v := newVerifier(t, issuer)
	rejects(t, v, pair.Sign(nil, nil), ReasonKeysUnavailable)
	if v.Status() != StatusOffline {
		t.Fatalf("status %s", v.Status())
	}
}

func TestVerifyStopsWaitingWhenTheCallerGoesAway(t *testing.T) {
	pair := tk.NewKeyPair("key-1", 0)
	issuer := tk.NewFakeIssuer(pair)
	issuer.Delay = time.Second
	v := newVerifier(t, issuer)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := v.Verify(ctx, pair.Sign(nil, nil))
	var rejected *TokenRejected
	if !errors.As(err, &rejected) || rejected.Reason != ReasonKeysUnavailable {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("waited for the fetch")
	}
	// The fetch goes on for the next caller, which is served.
	if _, err := v.Verify(context.Background(), pair.Sign(nil, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestATokenOfAnotherRealmIsRefused(t *testing.T) {
	// Each Provider has its own realm. A verifier for realm B refuses a token
	// of realm A, with A's own key and with a key both realms hold.
	shared := tk.NewKeyPair("key-1", 0)
	issuer := tk.NewFakeIssuer(shared)
	v := newVerifier(t, issuer)
	rejects(t, v, shared.Sign(map[string]any{"iss": "https://issuer.example.com/realms/other"}, nil), ReasonIssuer)
	rejects(t, v, tk.NewKeyPair("key-a", 1).Sign(map[string]any{"iss": "https://issuer.example.com/realms/other"}, nil), ReasonKid)
	if _, err := v.Verify(context.Background(), shared.Sign(nil, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestNewTokenVerifierRefusesAnOrgIDThatIsNotAUUID(t *testing.T) {
	if _, err := NewTokenVerifier(tk.Issuer, tk.Resource, "portal-labs", nil); err == nil {
		t.Fatal("no error")
	}
}
