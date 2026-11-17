package keelie

// Tell an agent where to get a token for your API.
//
// Two standard pieces, served from your own domain:
//
//   - The protected resource metadata (RFC 9728). It names your API and the one
//     issuer that mints tokens for it. An agent reads it at the well-known
//     address of your API. For https://api.example.com/mcp that is
//     https://api.example.com/.well-known/oauth-protected-resource/mcp.
//   - A 401 with WWW-Authenticate: Bearer resource_metadata="..." on a request
//     that carries no token (RFC 6750, RFC 9728 section 5). An agent finds the
//     metadata from this refusal. It does not read the header on a 200.
//
// The issuer serves its own authorization server metadata (RFC 8414). The SDK
// does not copy it: it names the issuer, and the agent reads the issuer.

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/apiable/keelie-sdk/go/internal/pyjson"
)

// WellKnown is the well-known name of the protected resource metadata.
const WellKnown = "/.well-known/oauth-protected-resource"

// Where an agent looks for the AI Catalog of a domain. ARD v0.91 reads
// ard.json and names no media type for it. The ai-catalog specification reads
// ai-catalog.json, and an MCP proposal points there. Both serve one body. A GET
// or a HEAD of either needs no token, but only once an [AICatalog] serves it.
const (
	ARDPath     = "/.well-known/ard.json"
	CatalogPath = "/.well-known/ai-catalog.json"
)

// CatalogMediaType is the media type of a catalog path, and false for any other
// path. It is the one list of those paths: the guards and the catalog both read it.
func CatalogMediaType(path string) (string, bool) {
	switch path {
	case ARDPath:
		return "application/json", true
	case CatalogPath:
		return "application/ai-catalog+json", true
	}
	return "", false
}

// Printable ASCII with no space, quote or backslash: the URL goes inside a
// quoted string of the header, as it is.
var urlChars = regexp.MustCompile(`^[!#-\[\]-~]+$`)

var errorCodes = regexp.MustCompile(`^[a-z_]+$`)

// httpsURL checks that value is an https URL with a host and no user, query,
// fragment or final slash, and gives its host (with the port) and its path.
//
// The scheme and the host must be lowercase: an uppercase one is refused, not
// folded. keelie stores your resource with the same rule and puts it into aud
// exactly, so the value here and the aud of a token compare equal.
func httpsURL(name, value string) (netloc, path string, err error) {
	if !urlChars.MatchString(value) {
		return "", "", fmt.Errorf("keelie: %s is not a URL: %q", name, value)
	}
	shape := fmt.Errorf("keelie: %s must be https, with a host, no user, query, fragment or final slash: %q", name, value)
	if len(value) < 8 || !strings.EqualFold(value[:8], "https://") {
		return "", "", shape
	}
	if strings.ContainsAny(value, "?#") {
		return "", "", shape
	}
	rest := value[8:]
	netloc, path = rest, ""
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		netloc, path = rest[:slash], rest[slash:]
	}
	if strings.Contains(netloc, "@") {
		return "", "", shape
	}
	host, port, hasPort := netloc, "", false
	if strings.HasPrefix(netloc, "[") {
		end := strings.IndexByte(netloc, ']')
		if end < 0 {
			return "", "", shape
		}
		host = netloc[:end+1]
		if after := netloc[end+1:]; after != "" {
			if after[0] != ':' {
				return "", "", shape
			}
			port, hasPort = after[1:], true
		}
		inner := host[1 : len(host)-1]
		if addr, err := netip.ParseAddr(inner); (err != nil || !addr.Is6()) && !strings.HasPrefix(inner, "v") {
			return "", "", shape
		}
	} else if colon := strings.IndexByte(netloc, ':'); colon >= 0 {
		host, port, hasPort = netloc[:colon], netloc[colon+1:], true
	}
	if host == "" || strings.ContainsAny(strings.Trim(host, "[]"), "[]") {
		return "", "", shape
	}
	if hasPort && port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 || strings.TrimLeft(port, "0123456789") != "" {
			return "", "", fmt.Errorf("keelie: %s has a port that is not a number: %q", name, value)
		}
	}
	if path != "" && path != "/" && strings.HasSuffix(path, "/") {
		return "", "", shape
	}
	if !strings.HasPrefix(value, "https://") || netloc != strings.ToLower(netloc) {
		return "", "", fmt.Errorf("keelie: %s must have a lowercase scheme and host: %q", name, value)
	}
	return netloc, path, nil
}

// ProtectedResourceMetadataOptions are the options of
// [NewProtectedResourceMetadata]. The zero value is the default.
type ProtectedResourceMetadataOptions struct {
	// ScopesSupported is published only if it is not nil.
	ScopesSupported []string
}

// ProtectedResourceMetadata is the RFC 9728 metadata of your API, and the
// challenge that points to it.
type ProtectedResourceMetadata struct {
	resource  string
	prefix    string
	path      string
	url       string
	document  []byte
	aiCatalog atomic.Bool
}

// NewProtectedResourceMetadata makes the metadata. resource is the URL an agent
// types for your API, exactly, path included: https, a lowercase host, no
// query, fragment or final slash. The metadata repeats it as it is.
// authorizationServer is the issuer, the same value you give
// [NewTokenVerifier]. It is one issuer: an agent uses the first and does not
// try a second. opts may be nil.
func NewProtectedResourceMetadata(resource, authorizationServer string, opts *ProtectedResourceMetadataOptions) (*ProtectedResourceMetadata, error) {
	netloc, path, err := httpsURL("resource", resource)
	if err != nil {
		return nil, err
	}
	if _, _, err := httpsURL("authorizationServer", authorizationServer); err != nil {
		return nil, err
	}
	m := &ProtectedResourceMetadata{resource: resource}
	// The well-known name goes between the host and the path (RFC 9728 section 3.1).
	m.prefix = strings.TrimRight(path, "/")
	m.path = WellKnown + m.prefix
	// From the configuration, never from the request's Host.
	m.url = "https://" + netloc + m.path

	var b bytes.Buffer
	b.WriteString(`{"resource":`)
	pyjson.String(&b, resource)
	b.WriteString(`,"authorization_servers":[`)
	pyjson.String(&b, authorizationServer)
	b.WriteString(`],"bearer_methods_supported":["header"]`)
	if opts != nil && opts.ScopesSupported != nil {
		b.WriteString(`,"scopes_supported":[`)
		for i, scope := range opts.ScopesSupported {
			if !isOneScope(scope) {
				return nil, fmt.Errorf("keelie: not one scope each: %q", opts.ScopesSupported)
			}
			if i > 0 {
				b.WriteByte(',')
			}
			pyjson.String(&b, scope)
		}
		b.WriteByte(']')
	}
	b.WriteByte('}')
	m.document = b.Bytes()
	return m, nil
}

// Resource is the resource, as given.
func (m *ProtectedResourceMetadata) Resource() string { return m.resource }

// Path is where the metadata is served on your host, such as
// /.well-known/oauth-protected-resource/v1.
func (m *ProtectedResourceMetadata) Path() string { return m.path }

// URL is the full URL of the metadata, from the configuration, never from the
// request's Host.
func (m *ProtectedResourceMetadata) URL() string { return m.url }

// ResourcePath is the path of the resource, with no final slash: "" for a
// resource at the root.
func (m *ProtectedResourceMetadata) ResourcePath() string { return m.prefix }

// Document is the JSON document, as served.
func (m *ProtectedResourceMetadata) Document() []byte { return bytes.Clone(m.document) }

// ServesAICatalog is true once an [AICatalog] is made with this metadata. Until
// then the catalog paths are guarded like any other.
func (m *ProtectedResourceMetadata) ServesAICatalog() bool { return m.aiCatalog.Load() }

// Challenge is the WWW-Authenticate value. Give "" for a request with no
// token, "invalid_token" for a refused token and "insufficient_scope" for a
// token that lacks the scope. It panics on a code that is not lowercase
// letters and underscores, which would break the header.
func (m *ProtectedResourceMetadata) Challenge(errorCode string) string {
	if errorCode == "" {
		return `Bearer resource_metadata="` + m.url + `"`
	}
	if !errorCodes.MatchString(errorCode) {
		panic(fmt.Sprintf("keelie: not an RFC 6750 error code: %q", errorCode))
	}
	return `Bearer error="` + errorCode + `", resource_metadata="` + m.url + `"`
}

// Protects is true for the path of the resource and every path below it.
func (m *ProtectedResourceMetadata) Protects(path string) bool {
	return m.prefix == "" || path == m.prefix || strings.HasPrefix(path, m.prefix+"/")
}

// BearerToken is the Bearer token in an Authorization header value, and false
// when there is none. The token is not checked.
func BearerToken(authorization string) (string, bool) {
	value := strings.TrimSpace(authorization)
	scheme, token := value, ""
	if at := strings.IndexByte(value, ' '); at >= 0 {
		scheme, token = value[:at], strings.TrimSpace(value[at+1:])
	}
	if !strings.EqualFold(scheme, "bearer") || token == "" {
		return "", false
	}
	return token, true
}
