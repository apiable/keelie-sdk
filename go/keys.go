package keelie

// The issuer's signing keys, kept in the process.
//
// The first token fetches the key set: the issuer's discovery document names its
// jwks_uri, and that document holds the keys. A kid the cache does not know
// fetches once more, then is refused. That is how a rotated key is picked up
// without a restart: the first token it signs fetches it.
//
// Once a key set is in hand, at most one fetch a minute, however many unknown
// kid values arrive and whether or not the fetch succeeds. A flood of made-up
// kid values costs the issuer one request a minute, also while the issuer is
// down. With no key set in hand, a failed fetch caches nothing, and the next
// caller tries again.
//
// The jwks_uri from the first discovery is kept for the life of the process. A
// discovery document whose issuer is not the configured one is refused, and no
// key is fetched from it (OpenID Connect Discovery 1.0, section 4.3). Each
// Provider has its own realm, so each issuer has its own key set: a document of
// another realm must never fill this one's.

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/apiable/keelie-sdk/go/internal/logx"
)

// Algorithm is the one algorithm the SDK accepts, in the key set and on the token.
const Algorithm = "RS256"

// RefreshInterval is how long the cache refuses a second fetch after one
// completed. Shorter than any token lifetime, so a rotation is never waited out.
const RefreshInterval = 60 * time.Second

// FetchTimeout is how long one request to the issuer may take.
const FetchTimeout = 5 * time.Second

// An RSA key under this size is skipped: it is too weak to trust.
const minModulusBits = 2048

// Status is what the SDK knows of the issuer, from its last fetch of the key set.
type Status string

const (
	// StatusConnected means the last fetch worked.
	StatusConnected Status = "connected"
	// StatusDegraded means the last fetch failed. The keys in hand go on verifying.
	StatusDegraded Status = "degraded"
	// StatusOffline means no key is in hand, so every token is refused.
	StatusOffline Status = "offline"
)

var (
	// ErrUnknownKey means no key in the set has this kid, after one refresh.
	ErrUnknownKey = errors.New("keelie: no key in the key set has this kid")
	// ErrKeysUnavailable means the key set could not be fetched, and no key set is in hand.
	ErrKeysUnavailable = errors.New("keelie: the key set could not be fetched")
)

// SigningKeysOptions are the options of [NewSigningKeys]. The zero value is the default.
type SigningKeysOptions struct {
	// HTTPClient fetches the discovery document and the key set. By default a
	// client that follows no redirect, as in Python. Each request gets
	// [FetchTimeout].
	HTTPClient *http.Client
	// Clock tells the time. time.Now unless you give another, such as in a test.
	Clock func() time.Time
	// RefreshInterval is [RefreshInterval] unless you give another.
	RefreshInterval time.Duration
}

// SigningKeys are the issuer's RS256 signing keys, fetched on first use and
// refreshed on an unknown kid. They are safe for concurrent use.
type SigningKeys struct {
	issuer   string
	client   *http.Client
	clock    func() time.Time
	interval time.Duration

	mu            sync.Mutex
	keys          map[string]*rsa.PublicKey
	jwksURI       string
	fetched       bool // a fetch has completed, so the cache is warm
	fetchedAt     time.Time
	refreshFailed bool
	inFlight      *refreshCall
}

type refreshCall struct {
	done chan struct{}
	err  error // set on a cold failure, which every waiter shares
}

// NewSigningKeys makes the key set of issuer: the issuer member of your org in
// keelie. opts may be nil.
func NewSigningKeys(issuer string, opts *SigningKeysOptions) *SigningKeys {
	k := &SigningKeys{
		issuer:   strings.TrimRight(issuer, "/"),
		clock:    time.Now,
		interval: RefreshInterval,
		keys:     map[string]*rsa.PublicKey{},
	}
	if opts != nil {
		k.client = opts.HTTPClient
		if opts.Clock != nil {
			k.clock = opts.Clock
		}
		if opts.RefreshInterval > 0 {
			k.interval = opts.RefreshInterval
		}
	}
	if k.client == nil {
		k.client = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return k
}

// Key returns the key with this kid, fetching the set once if it is not there.
// It returns an error that wraps [ErrUnknownKey] or [ErrKeysUnavailable].
func (k *SigningKeys) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	if key := k.keys[kid]; key != nil {
		k.mu.Unlock()
		return key, nil
	}
	// Every caller that finds the cache cold, or its kid missing, waits on the
	// same fetch. The issuer answers one request, not one for each caller.
	for k.inFlight != nil {
		call := k.inFlight
		k.mu.Unlock()
		if err := wait(ctx, call); err != nil {
			return nil, err
		}
		k.mu.Lock()
	}
	if k.keys[kid] == nil && k.mayFetch() {
		call := &refreshCall{done: make(chan struct{})}
		k.inFlight = call
		k.mu.Unlock()
		// The fetch runs on its own, so that a caller that goes away does not
		// fail it for the others.
		go k.refresh(call)
		if err := wait(ctx, call); err != nil {
			return nil, err
		}
		k.mu.Lock()
	}
	key := k.keys[kid]
	k.mu.Unlock()
	if key == nil {
		return nil, ErrUnknownKey
	}
	return key, nil
}

func wait(ctx context.Context, call *refreshCall) error {
	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrKeysUnavailable, ctx.Err())
	}
}

// Status is StatusOffline with no key, StatusDegraded if the last fetch
// failed, else StatusConnected. It makes no network call.
func (k *SigningKeys) Status() Status {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.keys) == 0 {
		return StatusOffline
	}
	if k.refreshFailed {
		return StatusDegraded
	}
	return StatusConnected
}

func (k *SigningKeys) mayFetch() bool {
	return !k.fetched || k.clock().Sub(k.fetchedAt) >= k.interval
}

func (k *SigningKeys) refresh(call *refreshCall) {
	keySet, err := k.fetchKeySet()
	var keys map[string]*rsa.PublicKey
	if err == nil {
		keys, err = signingKeys(keySet)
	}
	k.mu.Lock()
	defer func() {
		k.inFlight = nil
		k.mu.Unlock()
		close(call.done)
	}()
	if err != nil {
		if !k.fetched {
			// Cold: nothing to verify with. Nothing is cached, so the next
			// caller tries again.
			logx.Warn("apiable.keys_unavailable", "error", errorName(err))
			call.err = fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
			return
		}
		// Warm: the keys in hand go on verifying, and the issuer is not asked
		// again for another interval.
		k.fetchedAt = k.clock()
		k.refreshFailed = true
		logx.Warn("apiable.keys_not_refreshed", "error", errorName(err))
		return
	}
	k.keys = keys
	k.fetched = true
	k.fetchedAt = k.clock()
	k.refreshFailed = false
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	logx.Info("apiable.keys_loaded", "kids", kids)
}

func (k *SigningKeys) fetchKeySet() (any, error) {
	k.mu.Lock()
	jwksURI := k.jwksURI
	k.mu.Unlock()
	if jwksURI == "" {
		document, err := k.getJSON(k.issuer + "/.well-known/openid-configuration")
		if err != nil {
			return nil, err
		}
		issuer, err := member(document, "issuer")
		if err != nil {
			return nil, err
		}
		if s, ok := issuer.(string); !ok || strings.TrimRight(s, "/") != k.issuer {
			return nil, &fetchError{"issuer"}
		}
		uri, err := member(document, "jwks_uri")
		if err != nil {
			return nil, err
		}
		s, ok := uri.(string)
		if !ok {
			return nil, &fetchError{"jwks_uri"}
		}
		jwksURI = s
	}
	document, err := k.getJSON(jwksURI)
	if err != nil {
		return nil, err
	}
	keySet, err := member(document, "keys")
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	k.jwksURI = jwksURI
	k.mu.Unlock()
	return keySet, nil
}

func (k *SigningKeys) getJSON(url string) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &fetchError{"url"}
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &fetchError{fmt.Sprintf("status %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, &fetchError{"json"}
	}
	return document, nil
}

// fetchError is a fetch that failed for a reason the SDK names in its log.
type fetchError struct{ kind string }

func (e *fetchError) Error() string { return "keelie: " + e.kind }

// errorName is a fixed word for the log, never the error's own text.
func errorName(err error) string {
	var fe *fetchError
	var ne net.Error
	switch {
	case errors.As(err, &fe):
		return fe.kind
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	default:
		return "network"
	}
}

func member(document any, name string) (any, error) {
	object, ok := document.(map[string]any)
	if !ok {
		return nil, &fetchError{"document"}
	}
	value, ok := object[name]
	if !ok {
		return nil, &fetchError{name}
	}
	return value, nil
}

func signingKeys(keySet any) (map[string]*rsa.PublicKey, error) {
	list, ok := keySet.([]any)
	if !ok {
		return nil, &fetchError{"keys"}
	}
	keys := map[string]*rsa.PublicKey{}
	for _, item := range list {
		jwk, ok := item.(map[string]any)
		if !ok {
			continue
		}
		// The issuer can publish an encryption key beside the signing key. Only
		// an RSA key for signing, with the one algorithm and a kid, verifies a token.
		kid, ok := jwk["kid"].(string)
		if !ok || jwk["kty"] != "RSA" ||
			(jwk["use"] != nil && jwk["use"] != "sig") ||
			(jwk["alg"] != nil && jwk["alg"] != Algorithm) {
			continue
		}
		key, ok := publicKey(jwk)
		if !ok {
			// A key the SDK cannot load is skipped. The rest of the set loads.
			logx.Warn("apiable.key_skipped", "kid", kid)
			continue
		}
		keys[kid] = key
	}
	return keys, nil
}

// publicKey reads the public members of an RSA key only: a private member
// published by mistake is never loaded.
func publicKey(jwk map[string]any) (*rsa.PublicKey, bool) {
	n, ok := base64UInt(jwk["n"])
	if !ok || n.BitLen() < minModulusBits {
		return nil, false
	}
	e, ok := base64UInt(jwk["e"])
	// The exponent rules of crypto/rsa: odd, at least 3, and an int32.
	if !ok || e.BitLen() > 31 || e.Int64() < 3 || e.Bit(0) == 0 {
		return nil, false
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, true
}

func base64UInt(value any) (*big.Int, bool) {
	s, ok := value.(string)
	if !ok {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}
