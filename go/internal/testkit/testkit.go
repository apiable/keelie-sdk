// Package testkit is a fake issuer, signed tokens and a clock for the SDK's
// own tests. No network: the issuer answers inside the process.
package testkit

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	Issuer   = "https://issuer.example.com/realms/portal-labs"
	JWKSURI  = Issuer + "/protocol/openid-connect/certs"
	Resource = "https://api.example.com/v1"
	OrgID    = "6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12"
	OtherOrg = "0f2e1d3c-5b4a-4968-8776-a5b4c3d2e1f0"
	Consumer = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
)

// KeyPair is a signing key and the JWK of its public half.
type KeyPair struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	JWK        map[string]any
}

var (
	keysMu sync.Mutex
	keys   []*rsa.PrivateKey
)

// NewKeyPair is an RS256 key pair with this kid. The RSA keys are made once
// and reused across the tests, in order: the nth call in a test run with a new
// index gets a new key.
func NewKeyPair(kid string, index int) *KeyPair {
	return pairOf(kid, rsaKey(index, 2048))
}

// rsaKey is the index-th key of this size, made once.
func rsaKey(index, bits int) *rsa.PrivateKey {
	keysMu.Lock()
	defer keysMu.Unlock()
	for len(keys) <= index {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			panic(err)
		}
		keys = append(keys, k)
	}
	return keys[index]
}

func pairOf(kid string, key *rsa.PrivateKey) *KeyPair {
	return &KeyPair{Kid: kid, PrivateKey: key, JWK: map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   b64(key.N.Bytes()),
		"e":   b64(big.NewInt(int64(key.E)).Bytes()),
	}}
}

// WithKid is a copy of the JWK with another kid and members.
func (p *KeyPair) WithKid(kid string, extra map[string]any) map[string]any {
	jwk := map[string]any{}
	for k, v := range p.JWK {
		jwk[k] = v
	}
	jwk["kid"] = kid
	for k, v := range extra {
		if v == nil {
			delete(jwk, k)
		} else {
			jwk[k] = v
		}
	}
	return jwk
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Remove marks a claim to leave out of a token.
var Remove = struct{ remove bool }{true}

// Claims are the claims of a Consumer's token, by the token rules, with extra
// laid over them. A claim given as Remove is left out.
func Claims(extra map[string]any) map[string]any {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":    Issuer,
		"aud":    Resource,
		"azp":    "consumer-client",
		"org_id": OrgID,
		"scope":  "orders:read profile",
		"typ":    "Bearer",
		"jti":    "token-1",
		"iat":    now,
		"exp":    now + 300,
	}
	for k, v := range extra {
		if v == Remove {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return claims
}

// Sign is a token signed with p, with the claims of [Claims] and header laid
// over {"alg": "RS256", "kid": p.Kid}.
func (p *KeyPair) Sign(extra map[string]any, header map[string]any) string {
	h := map[string]any{"alg": "RS256", "kid": p.Kid}
	for k, v := range header {
		if v == Remove {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	input := part(h) + "." + part(Claims(extra))
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(sig)
}

// SignRaw signs header and payload segments as given.
func (p *KeyPair) SignRaw(header, payload string) string {
	input := b64([]byte(header)) + "." + b64([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(sig)
}

// Unsigned is a token with any header, for the checks that run before a key is fetched.
func Unsigned(header map[string]any) string {
	return part(header) + "." + part(Claims(nil)) + "." + b64([]byte("sig"))
}

func part(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b64(b)
}

// FakeIssuer serves its discovery document and key set, and counts the requests.
type FakeIssuer struct {
	mu              sync.Mutex
	Keys            []any
	Down            bool
	DiscoveryIssuer string
	Requests        []string
	// Delay is how long each answer takes, so that concurrent callers overlap.
	Delay time.Duration
}

// NewFakeIssuer serves the keys of pairs.
func NewFakeIssuer(pairs ...*KeyPair) *FakeIssuer {
	f := &FakeIssuer{DiscoveryIssuer: Issuer, Delay: 10 * time.Millisecond}
	for _, p := range pairs {
		f.Keys = append(f.Keys, p.JWK)
	}
	return f
}

// Set changes the issuer under its lock.
func (f *FakeIssuer) Set(change func(f *FakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// Seen is the requests so far, and forgets them.
func (f *FakeIssuer) Seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := f.Requests
	f.Requests = nil
	return seen
}

// Client is an http.Client whose requests this issuer answers.
func (f *FakeIssuer) Client() *http.Client { return &http.Client{Transport: f} }

// RoundTrip answers one request.
func (f *FakeIssuer) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	url := req.URL.String()
	f.Requests = append(f.Requests, url)
	down, delay, discovery, keys := f.Down, f.Delay, f.DiscoveryIssuer, f.Keys
	f.mu.Unlock()
	select {
	case <-time.After(delay):
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	if down {
		return nil, errors.New("fetch failed")
	}
	switch url {
	case Issuer + "/.well-known/openid-configuration":
		return JSON(http.StatusOK, map[string]any{"issuer": discovery, "jwks_uri": JWKSURI}), nil
	case JWKSURI:
		return JSON(http.StatusOK, map[string]any{"keys": keys}), nil
	}
	return JSON(http.StatusNotFound, map[string]any{}), nil
}

// JSON is a response with v as its body.
func JSON(status int, v any) *http.Response {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return Response(status, b)
}

// Response is a response with body.
func Response(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// Clock is a clock the test moves by hand.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock starts at a fixed time.
func NewClock() *Clock { return &Clock{now: time.Unix(1_000_000, 0)} }

// Now reads the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock on.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Until waits until check is true, or fails after two seconds.
func Until(check func() bool) error {
	end := time.Now().Add(2 * time.Second)
	for !check() {
		if time.Now().After(end) {
			return errors.New("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// SmallKeyPair is a pair whose RSA key has bits bits, for the key-size checks.
func SmallKeyPair(kid string, bits int) *KeyPair {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return pairOf(kid, k)
}
