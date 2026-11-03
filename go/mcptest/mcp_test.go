// Package mcptest runs a real MCP client and server, from the official Go MCP
// SDK, through the guard. It is a module of its own so that the SDK itself has
// no dependency: the MCP SDK needs a newer Go than the SDK does.
package mcptest

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	keelie "github.com/apiable/keelie-sdk/go"
	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
	"github.com/apiable/keelie-sdk/go/nethttp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const resource = "https://api.example.com/mcp"

// bearer adds a token to each request of the MCP client.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

type events struct {
	mu   sync.Mutex
	list []map[string]string
}

func (e *events) Send(_ context.Context, _, _ string, _ http.Header, body []byte) (*http.Response, error) {
	var decoded struct {
		Events []map[string]string `json:"events"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.list = append(e.list, decoded.Events...)
	e.mu.Unlock()
	return tk.JSON(202, map[string]any{}), nil
}

type none struct{}

func text(s string) mcp.ToolHandlerFor[none, any] {
	return func(context.Context, *mcp.CallToolRequest, none) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}, nil, nil
	}
}

func TestARealMCPClientListsAndCallsAToolItsTokenAllowsAndTheCallIsCounted(t *testing.T) {
	keelie.SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for name, options := range map[string]*mcp.StreamableHTTPOptions{
		"event stream": nil,
		"JSON":         {JSONResponse: true},
	} {
		t.Run(name, func(t *testing.T) {
			pair := tk.NewKeyPair("key-1", 0)
			keys := keelie.NewSigningKeys(tk.Issuer, &keelie.SigningKeysOptions{HTTPClient: tk.NewFakeIssuer(pair).Client()})
			verifier, err := keelie.NewTokenVerifier(tk.Issuer, resource, tk.OrgID, &keelie.TokenVerifierOptions{Keys: keys})
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := keelie.NewProtectedResourceMetadata(resource, tk.Issuer, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent := &events{}
			reporter, err := keelie.NewUsageReporter(sent, &keelie.UsageReporterOptions{BatchSize: 1, FlushInterval: 20 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			guard, err := nethttp.MCPGuard(nethttp.MCPGuardOptions{
				Verifier: verifier,
				Metadata: metadata,
				Tools:    map[string]string{"classify": "classify:run", "delete_all": "admin"},
				Reporter: reporter,
			})
			if err != nil {
				t.Fatal(err)
			}

			server := mcp.NewServer(&mcp.Implementation{Name: "product-classifier", Version: "1.0.0"}, nil)
			mcp.AddTool(server, &mcp.Tool{Name: "classify", Description: "Classify a product"}, text("Apparel > Shoes"))
			mcp.AddTool(server, &mcp.Tool{Name: "delete_all", Description: "Delete everything"}, text("gone"))
			mux := http.NewServeMux()
			mux.Handle("/mcp", guard(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, options)))
			srv := httptest.NewServer(mux)
			defer srv.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			token := pair.Sign(map[string]any{"aud": resource, "scope": "classify:run", "consumer_id": tk.Consumer, "azp": "claude"}, nil)
			client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1.0.0"}, nil)
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint:   srv.URL + "/mcp",
				HTTPClient: &http.Client{Transport: bearer{token}},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			listed, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, tool := range listed.Tools {
				names = append(names, tool.Name)
			}
			slices.Sort(names)
			if !slices.Equal(names, []string{"classify", "delete_all"}) {
				t.Fatalf("tools %v", names)
			}
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "classify", Arguments: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "Apparel > Shoes" {
				t.Fatalf("result %+v", result.Content)
			}
			if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "delete_all", Arguments: map[string]any{}}); err == nil {
				t.Fatal("a tool the token lacks was called")
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}

			reporter.Close(context.Background())
			sent.mu.Lock()
			defer sent.mu.Unlock()
			if len(sent.list) != 1 {
				t.Fatalf("events %v", sent.list)
			}
			e := sent.list[0]
			if e["unit"] != "tool_call" || e["capability_key"] != "classify" || e["client_id"] != "claude" || e["consumer_id"] != tk.Consumer {
				t.Fatalf("event %v", e)
			}
			if _, ok := e["credits"]; ok {
				t.Fatalf("event %v", e)
			}
		})
	}
}

func TestAClientWithNoTokenIsRefusedAndToldWhereToGetOne(t *testing.T) {
	metadata, err := keelie.NewProtectedResourceMetadata(resource, tk.Issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := keelie.NewSigningKeys(tk.Issuer, &keelie.SigningKeysOptions{HTTPClient: tk.NewFakeIssuer().Client()})
	verifier, _ := keelie.NewTokenVerifier(tk.Issuer, resource, tk.OrgID, &keelie.TokenVerifierOptions{Keys: keys})
	reporter, _ := keelie.NewUsageReporter(&events{}, nil)
	defer reporter.Close(context.Background())
	guard, err := nethttp.MCPGuard(nethttp.MCPGuardOptions{Verifier: verifier, Metadata: metadata, Tools: map[string]string{}, Reporter: reporter})
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "s", Version: "1"}, nil)
	srv := httptest.NewServer(guard(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1.0.0"}, nil)
	if _, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp", MaxRetries: -1}, nil); err == nil {
		t.Fatal("connected with no token")
	}
	res, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("metadata: %d", res.StatusCode)
	}
}
