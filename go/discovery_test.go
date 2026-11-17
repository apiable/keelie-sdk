package keelie

import (
	"testing"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

func TestMetadataIsServedBetweenTheHostAndThePath(t *testing.T) {
	m, err := NewProtectedResourceMetadata("https://api.example.com/v1", tk.Issuer, &ProtectedResourceMetadataOptions{
		ScopesSupported: []string{"orders:read", "été"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Path() != "/.well-known/oauth-protected-resource/v1" {
		t.Fatal(m.Path())
	}
	if m.URL() != "https://api.example.com/.well-known/oauth-protected-resource/v1" {
		t.Fatal(m.URL())
	}
	// The bytes Python's json.dumps writes, with every non-ASCII character escaped.
	want := `{"resource":"https://api.example.com/v1","authorization_servers":["https://issuer.example.com/realms/portal-labs"],"bearer_methods_supported":["header"],"scopes_supported":["orders:read","\u00e9t\u00e9"]}`
	if string(m.Document()) != want {
		t.Fatalf("document %s", m.Document())
	}
	if m.Challenge("") != `Bearer resource_metadata="`+m.URL()+`"` {
		t.Fatal(m.Challenge(""))
	}
	if m.Challenge("invalid_token") != `Bearer error="invalid_token", resource_metadata="`+m.URL()+`"` {
		t.Fatal(m.Challenge("invalid_token"))
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic for a code that would break the header")
			}
		}()
		m.Challenge(`x", evil="1`)
	}()
	for path, want := range map[string]bool{"/v1": true, "/v1/orders": true, "/v10": false, "/health": false} {
		if m.Protects(path) != want {
			t.Fatalf("Protects(%q)", path)
		}
	}
	if m.ServesAICatalog() {
		t.Fatal("no catalog yet")
	}
}

func TestMetadataPublishesNoScopesUnlessGiven(t *testing.T) {
	m, err := NewProtectedResourceMetadata(tk.Resource, tk.Issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"resource":"https://api.example.com/v1","authorization_servers":["https://issuer.example.com/realms/portal-labs"],"bearer_methods_supported":["header"]}`
	if string(m.Document()) != want {
		t.Fatalf("document %s", m.Document())
	}
	m, err = NewProtectedResourceMetadata(tk.Resource, tk.Issuer, &ProtectedResourceMetadataOptions{ScopesSupported: []string{}})
	if err != nil || string(m.Document()) != want[:len(want)-1]+`,"scopes_supported":[]}` {
		t.Fatalf("an empty list is published: %s %v", m.Document(), err)
	}
	if _, err := NewProtectedResourceMetadata(tk.Resource, tk.Issuer, &ProtectedResourceMetadataOptions{ScopesSupported: []string{"a b"}}); err == nil {
		t.Fatal("two scopes in one")
	}
}

func TestAResourceAtTheRootProtectsEveryPath(t *testing.T) {
	for _, resource := range []string{"https://api.example.com", "https://api.example.com/"} {
		m, err := NewProtectedResourceMetadata(resource, tk.Issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		if m.Path() != "/.well-known/oauth-protected-resource" || !m.Protects("/anything") || m.ResourcePath() != "" {
			t.Fatal(resource)
		}
	}
}

func TestOnlyAPlainLowercaseHTTPSURLIsTaken(t *testing.T) {
	for _, bad := range []string{
		"http://api.example.com",
		"https://API.example.com",
		"HTTPS://api.example.com",
		"https://api.example.com/v1/",
		"https://api.example.com/v1?x=1",
		"https://api.example.com/v1#x",
		"https://user@api.example.com",
		"https://api.example.com:http",
		"https://api.example.com:70000",
		"https://api.example.com:+1",
		"https:///v1",
		"https://:443/v1",
		"https://[::1",
		"https://[]/v1",
		"https://[1.2.3.4]/v1",
		"https://api]example.com",
		`https://api.example.com/"`,
		`https://api.example.com/a\b`,
		"https://api.example.com/a b",
		"https://api.example.com/é",
		"",
	} {
		if _, err := NewProtectedResourceMetadata(bad, tk.Issuer, nil); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	for _, good := range []string{"https://api.example.com:8443/mcp", "https://[::1]:8443/mcp", "https://api.example.com:/v1", "https://api.example.com/V1"} {
		if _, err := NewProtectedResourceMetadata(good, tk.Issuer, nil); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	if _, err := NewProtectedResourceMetadata(tk.Resource, "http://issuer.example.com", nil); err == nil {
		t.Error("the issuer must be https too")
	}
}

func TestBearerTokenReadsTheTokenOfABearerHeaderAndNothingElse(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":     "abc",
		"bearer   abc  ": "abc",
		"  BEARER abc":   "abc",
		"Basic abc":      "",
		"Bearer":         "",
		"Bearer ":        "",
		"":               "",
		"Bearer\tabc":    "",
		"Bearer abc def": "abc def",
		"Bearerabc":      "",
	} {
		got, ok := BearerToken(header)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v", header, got, ok)
		}
	}
}
