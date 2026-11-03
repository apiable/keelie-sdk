package keelie

// Verify an access token inside your own process.
//
// The SDK never asks Apiable whether a token is good. It checks the signature
// against the issuer's key set (see keys.go) and the claims against what you
// configured. The checks run in this order, and the first that fails refuses the
// token:
//
//  1. The token parses, its alg is RS256 and it names a kid. A token that says
//     none or HS256 is refused before any key is fetched.
//  2. The key with that kid is in the issuer's key set.
//  3. The signature, exp (required), nbf, iat, iss and aud.
//  4. azp names the client, and org_id is your own org id.
//  5. typ is Bearer. An ID token is signed with the same key.
//
// The issuer is your own realm: the issuer member of your org in keelie. Each
// Provider has its own realm, with its own iss and its own key set, so a token
// of another Provider fails at step 2 or 3. The org_id check stays as a second
// line: a Provider whose Consumers keelie made before it had a realm shares one
// issuer and one key set with others, and there org_id tells them apart.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/apiable/keelie-sdk/go/internal/logx"
)

const tokenType = "Bearer"

// Leeway is the clock skew a token is forgiven.
const Leeway = 30 * time.Second

// The largest exp that Python's datetime holds: the last second of the year 9999.
const maxExp = 253402300799

// Reason is why a token was refused. It is for your log, never for the caller:
// a caller must not learn "expired" from "wrong key".
type Reason string

// The reasons a token is refused, the same as in Python.
const (
	ReasonMalformed       Reason = "malformed"
	ReasonAlgorithm       Reason = "algorithm"
	ReasonKid             Reason = "kid"
	ReasonKeysUnavailable Reason = "keys_unavailable"
	ReasonSignature       Reason = "signature"
	ReasonExpired         Reason = "expired"
	ReasonNotYetValid     Reason = "not_yet_valid"
	ReasonIssuer          Reason = "issuer"
	ReasonAudience        Reason = "audience"
	ReasonClaims          Reason = "claims"
	ReasonOrg             Reason = "org"
	ReasonTyp             Reason = "typ"
)

// TokenRejected is the error of every token that does not verify.
type TokenRejected struct {
	Reason Reason
}

func (e *TokenRejected) Error() string { return "keelie: token rejected: " + string(e.Reason) }

// Claims are the claims of a verified token that the SDK reads.
type Claims struct {
	// AZP is the client the token was issued to: the credential. sub names the
	// issuer's own service-account user and is ignored.
	AZP string
	// OrgID is your org id, lowercase with hyphens.
	OrgID string
	// Scopes are the scopes of the token, each once.
	Scopes []string
	// JTI is the token id, or "" when the token has none. Log it. Never log the token.
	JTI string
	// ExpiresAt is when the token expires, from exp, in UTC. While keelie is
	// down, the Consumer is served until then, and refused after.
	ExpiresAt time.Time
	// ConsumerID is set on a token for a person: the Consumer whose credits the
	// person uses, from the consumer_id claim, lowercase with hyphens. AZP is
	// then the agent's client, which serves every Consumer. It is "" on a
	// credential's token, which names its Consumer by AZP. Pass it to
	// [UsageReporter.Record] with AZP.
	ConsumerID string
}

// HasScope reports whether the token carries scope, exactly.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// TokenVerifierOptions are the options of [NewTokenVerifier]. The zero value is the default.
type TokenVerifierOptions struct {
	// Keys is the key set. One made from the issuer unless you give another,
	// such as in a test.
	Keys *SigningKeys
	// Leeway is the clock skew a token is forgiven. [Leeway] when zero; a
	// negative value forgives none.
	Leeway time.Duration
}

// TokenVerifier verifies the tokens of one issuer, for one audience and one
// org. It is safe for concurrent use. Make one for the process.
type TokenVerifier struct {
	issuer   string
	audience string
	orgID    string
	keys     *SigningKeys
	leeway   float64
}

// NewTokenVerifier makes the verifier. issuer is the issuer member of your org
// in keelie: your own realm. audience is your API's resource in keelie,
// exactly. orgID is your org id; a value that is not a UUID is an error. opts
// may be nil.
func NewTokenVerifier(issuer, audience, orgID string, opts *TokenVerifierOptions) (*TokenVerifier, error) {
	org, ok := parseUUID(orgID)
	if !ok {
		return nil, fmt.Errorf("keelie: orgID is not a UUID: %q", orgID)
	}
	v := &TokenVerifier{issuer: issuer, audience: audience, orgID: org, leeway: Leeway.Seconds()}
	if opts != nil {
		v.keys = opts.Keys
		if opts.Leeway > 0 {
			v.leeway = opts.Leeway.Seconds()
		} else if opts.Leeway < 0 {
			v.leeway = 0
		}
	}
	if v.keys == nil {
		v.keys = NewSigningKeys(issuer, nil)
	}
	return v, nil
}

// Audience is the aud every token must carry: your server's resource in keelie.
func (v *TokenVerifier) Audience() string { return v.audience }

// Status is what the SDK knows of the issuer, from its last fetch of the key set.
//
//   - StatusConnected: the last fetch worked.
//   - StatusDegraded: the last fetch failed. The keys in hand go on verifying.
//     The next fetch that works makes it StatusConnected again.
//   - StatusOffline: no key in hand, so every token is refused. A process is
//     offline until the first token fetches the key set.
//
// It makes no network call, and the SDK does not poll. The SDK fetches only on
// a cold start and for a key it does not know. So while the keys in hand verify
// every token, an outage of the issuer leaves the status as it is.
func (v *TokenVerifier) Status() Status { return v.keys.Status() }

// Verify returns the claims of the token, or a [*TokenRejected] with the reason.
// ctx bounds the wait for the key set, which is fetched on a cold start and for
// an unknown kid.
func (v *TokenVerifier) Verify(ctx context.Context, token string) (*Claims, error) {
	claims, reason := v.verify(ctx, token)
	if reason != "" {
		logx.Info("apiable.token_rejected", "reason", string(reason))
		return nil, &TokenRejected{Reason: reason}
	}
	return claims, nil
}

func (v *TokenVerifier) verify(ctx context.Context, token string) (*Claims, Reason) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ReasonMalformed
	}
	headerBytes, ok1 := segment(parts[0])
	payloadBytes, ok2 := segment(parts[1])
	signature, ok3 := segment(parts[2])
	if !ok1 || !ok2 || !ok3 {
		return nil, ReasonMalformed
	}
	header, ok := object(headerBytes)
	if !ok || !headerOK(header) {
		return nil, ReasonMalformed
	}
	if header["alg"] != Algorithm {
		return nil, ReasonAlgorithm
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, ReasonKid
	}

	key, err := v.keys.Key(ctx, kid)
	if errors.Is(err, ErrUnknownKey) {
		return nil, ReasonKid
	} else if err != nil {
		return nil, ReasonKeysUnavailable
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return nil, ReasonSignature
	}
	payload, ok := object(payloadBytes)
	if !ok {
		return nil, ReasonMalformed
	}

	// The claims, in the order PyJWT checks them.
	now := float64(time.Now().UnixNano()) / 1e9
	if payload["exp"] == nil {
		return nil, ReasonClaims
	}
	if raw, present := payload["iat"]; present {
		iat, ok := number(raw)
		if !ok {
			return nil, ReasonMalformed
		}
		if math.Trunc(iat) > now+v.leeway {
			return nil, ReasonNotYetValid
		}
	}
	if raw, present := payload["nbf"]; present {
		nbf, ok := number(raw)
		if !ok {
			return nil, ReasonMalformed
		}
		if math.Trunc(nbf) > now+v.leeway {
			return nil, ReasonNotYetValid
		}
	}
	exp, ok := number(payload["exp"])
	if !ok {
		return nil, ReasonMalformed
	}
	if math.Trunc(exp) <= now-v.leeway {
		return nil, ReasonExpired
	}
	iss, present := payload["iss"]
	if !present {
		return nil, ReasonClaims
	}
	if iss != v.issuer {
		return nil, ReasonIssuer
	}
	if !audienceOK(payload["aud"], v.audience) {
		return nil, ReasonAudience
	}
	for _, name := range []string{"sub", "jti"} {
		if raw, present := payload[name]; present {
			if _, ok := raw.(string); !ok {
				return nil, ReasonMalformed
			}
		}
	}

	// The claims keelie writes.
	orgRaw, _ := payload["org_id"].(string)
	orgID, ok := parseUUID(orgRaw)
	if !ok {
		return nil, ReasonClaims
	}
	azp, _ := payload["azp"].(string)
	scope := ""
	if raw, present := payload["scope"]; present {
		s, ok := raw.(string)
		if !ok {
			return nil, ReasonClaims
		}
		scope = s
	}
	if azp == "" {
		return nil, ReasonClaims
	}
	if orgID != v.orgID {
		return nil, ReasonOrg
	}
	if payload["typ"] != tokenType {
		return nil, ReasonTyp
	}
	if exp > maxExp {
		return nil, ReasonClaims
	}
	seconds, fraction := math.Modf(exp)
	expiresAt := time.Unix(int64(seconds), int64(fraction*1e9)).UTC()
	consumerID := ""
	if raw := payload["consumer_id"]; raw != nil {
		s, ok := raw.(string)
		if !ok {
			return nil, ReasonClaims
		}
		if consumerID, ok = parseUUID(s); !ok {
			return nil, ReasonClaims
		}
	}
	jti, _ := payload["jti"].(string)
	return &Claims{
		AZP:        azp,
		OrgID:      orgID,
		Scopes:     uniqueFields(scope),
		JTI:        jti,
		ExpiresAt:  expiresAt,
		ConsumerID: consumerID,
	}, ""
}

// segment decodes one part of a token: base64url with no padding, in its one
// canonical form, as PyJWT reads it.
func segment(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil
}

// object reads a JSON object, with its numbers kept as written.
func object(data []byte) (map[string]any, bool) {
	if !utf8.Valid(data) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	m, ok := value.(map[string]any)
	return m, ok
}

// headerOK applies PyJWT's header rules: kid, when present, is a string; crit
// names only b64, which must then be present; and the payload is never
// detached (b64 false).
func headerOK(header map[string]any) bool {
	if kid, present := header["kid"]; present {
		if _, ok := kid.(string); !ok {
			return false
		}
	}
	if crit, present := header["crit"]; present {
		list, ok := crit.([]any)
		if !ok || len(list) == 0 {
			return false
		}
		for _, ext := range list {
			if ext != "b64" {
				return false
			}
		}
		if _, ok := header["b64"]; !ok {
			return false
		}
	}
	return header["b64"] != false
}

func number(value any) (float64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// audienceOK: aud is the audience, or a list of strings that holds it.
func audienceOK(aud any, audience string) bool {
	switch a := aud.(type) {
	case string:
		return a != "" && a == audience
	case []any:
		found := false
		for _, item := range a {
			s, ok := item.(string)
			if !ok {
				return false
			}
			found = found || s == audience
		}
		return found
	}
	return false
}

// pyFields splits s at whitespace as Python's str.split() does.
func pyFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}

func uniqueFields(s string) []string {
	fields := pyFields(s)
	out := fields[:0]
	seen := map[string]bool{}
	for _, f := range fields {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
