package nethttp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	keelie "github.com/apiable/keelie-sdk/go"
	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
	"github.com/apiable/keelie-sdk/go/nethttp"
)

const mcpResource = "https://api.example.com/mcp"

// events collects the usage events keelie is sent.
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

func (e *events) all() []map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]map[string]string(nil), e.list...)
}

// server is an MCP server that records each body and answers with status.
type server struct {
	mu     sync.Mutex
	bodies []string
	claims []*keelie.Claims
	status int
	stream bool
	silent bool
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	claims, _ := nethttp.ClaimsFrom(r)
	s.mu.Lock()
	s.bodies = append(s.bodies, string(body))
	s.claims = append(s.claims, claims)
	status, stream, silent := s.status, s.stream, s.silent
	s.mu.Unlock()
	if silent {
		return
	}
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message\ndata: {}\n\n")
		_ = http.NewResponseController(w).Flush()
		return
	}
	if status == 0 {
		status = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
}

type mcpSetup struct {
	handler  http.Handler
	server   *server
	events   *events
	reporter *keelie.UsageReporter
	metadata *keelie.ProtectedResourceMetadata
}

func newMCP(t *testing.T) *mcpSetup {
	s := &mcpSetup{server: &server{}, events: &events{}, metadata: metadata(t, mcpResource)}
	s.reporter = must(keelie.NewUsageReporter(s.events, &keelie.UsageReporterOptions{BatchSize: 1, FlushInterval: 20 * time.Millisecond}))
	guard := must(nethttp.MCPGuard(nethttp.MCPGuardOptions{
		Verifier:     verifier(t, mcpResource),
		Metadata:     s.metadata,
		Tools:        map[string]string{"classify": "classify:run", "delete_all": "admin"},
		Reporter:     s.reporter,
		MaxBodyBytes: 4096,
	}))
	s.handler = guard(s.server)
	return s
}

// sent is the events after the reporter has sent all it holds.
func (s *mcpSetup) sent() []map[string]string {
	s.reporter.Close(context.Background())
	return s.events.all()
}

func mcpToken() string {
	return "Bearer " + pair.Sign(map[string]any{"aud": mcpResource, "scope": "classify:run", "consumer_id": tk.Consumer, "azp": "claude"}, nil)
}

func (s *mcpSetup) post(body string) *httptest.ResponseRecorder {
	return s.request("POST", body, mcpToken())
}

func (s *mcpSetup) request(method, body, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func rpcError(t *testing.T, res *httptest.ResponseRecorder, status, code int, id string) {
	t.Helper()
	if res.Code != status || res.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, %v: %s", res.Code, res.Header(), res.Body)
	}
	want := `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":` + itoa(code) + `,"message":`
	if !strings.HasPrefix(res.Body.String(), want) {
		t.Fatalf("body %s, want %s...", res.Body, want)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func call(id, name string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":` + name + `,"arguments":{}}}`
}

func TestAToolCallWithTheScopeReachesTheServerUnchangedAndIsCounted(t *testing.T) {
	s := newMCP(t)
	body := "{\"jsonrpc\":\"2.0\",  \"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"classify\",\"arguments\":{}}}\n"
	res := s.post(body)
	if res.Code != 200 {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if len(s.server.bodies) != 1 || s.server.bodies[0] != body {
		t.Fatalf("bodies %q", s.server.bodies)
	}
	if s.server.claims[0] == nil || s.server.claims[0].AZP != "claude" {
		t.Fatal("the server does not see the claims")
	}
	sent := s.sent()
	if len(sent) != 1 {
		t.Fatalf("events %v", sent)
	}
	e := sent[0]
	if e["unit"] != "tool_call" || e["capability_key"] != "classify" || e["client_id"] != "claude" || e["consumer_id"] != tk.Consumer || e["quantity"] != "1" {
		t.Fatalf("event %v", e)
	}
	if _, ok := e["credits"]; ok {
		t.Fatalf("event %v", e)
	}
}

func TestAToolTheTokenLacksOrThatIsNotMappedGets403AndNoScopeIsNamed(t *testing.T) {
	s := newMCP(t)
	for _, name := range []string{`"delete_all"`, `"not_a_tool"`} {
		res := s.post(call("7", name))
		if res.Header().Get("WWW-Authenticate") != s.metadata.Challenge("insufficient_scope") {
			t.Fatal(res.Header())
		}
		rpcError(t, res, 403, -31001, "7")
		if strings.Contains(res.Body.String(), "admin") {
			t.Fatal("the answer names the scope")
		}
	}
	// An id that is not ASCII is written back as Python writes it.
	res := s.post(call("\"a-é\"", `"delete_all"`))
	rpcError(t, res, 403, -31001, "\"a-\x5cu00e9\"")
	if len(s.server.bodies) != 0 || len(s.sent()) != 0 {
		t.Fatal("a refused call reached the server or was counted")
	}
}

func TestABodyTheGuardCannotCheckIsRefusedWithAJSONRPCError(t *testing.T) {
	s := newMCP(t)
	escaped := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify","` + "\x5c" + `u006eame":"delete_all"}}`
	for _, c := range []struct {
		body   string
		status int
		code   int
		id     string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify","name":"delete_all"}}`, 400, -32600, "null"},
		{escaped, 400, -32600, "null"},
		{`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}`, 400, -32600, "null"},
		{`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, 400, -32600, "null"},
		{`"just a string"`, 400, -32600, "null"},
		{`null`, 400, -32600, "null"},
		{`{not json`, 400, -32700, "null"},
		{``, 400, -32700, "null"},
		{`{"a":1} {"b":2}`, 400, -32700, "null"},
		{`{"a":NaN}`, 400, -32700, "null"},
		{strings.Repeat("[", 1001) + strings.Repeat("]", 1001), 400, -32700, "null"},
		{"\xef\xbb\xbf" + `{"jsonrpc":"2.0","id":1,"method":"ping"}`, 400, -32700, "null"},
		{`{"jsonrpc":"2.0","id":1,"method":"ping","x":"` + "\xff" + `"}`, 400, -32700, "null"},
		{`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"classify"}}`, 400, -32600, "null"},
		{call("true", `"classify"`), 400, -32600, "null"},
		{call("null", `"classify"`), 400, -32600, "null"},
		{call("1.5", `"classify"`), 400, -32600, "null"},
		{call("1e2", `"classify"`), 400, -32600, "null"},
		{call(`"a"`, "3"), 400, -32602, `"a"`},
		{call("-0", "3"), 400, -32602, "0"},
		{call("123456789012345678901234567890", "null"), 400, -32602, "123456789012345678901234567890"},
		{`{"jsonrpc":"2.0","id":7,"method":"tools/call"}`, 400, -32602, "7"},
		{`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":[]}`, 400, -32602, "7"},
		{call("1", `"`+strings.Repeat("x", 5000)+`"`), 413, -32600, "null"},
	} {
		res := s.post(c.body)
		rpcError(t, res, c.status, c.code, c.id)
	}
	// 1000 deep is read.
	if res := s.post(`{"jsonrpc":"2.0","id":1,"method":"ping","x":` + strings.Repeat("[", 999) + strings.Repeat("]", 999) + `}`); res.Code != 200 {
		t.Fatalf("1000 deep: %d %s", res.Code, res.Body)
	}
	if len(s.server.bodies) != 1 {
		t.Fatalf("a refused body reached the server: %d", len(s.server.bodies))
	}
}

func TestOtherMethodsPassWithNoScopeAndCountNothing(t *testing.T) {
	s := newMCP(t)
	for _, method := range []string{"initialize", "notifications/initialized", "ping", "tools/list", "resources/read"} {
		res := s.request("POST", `{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`,
			"Bearer "+pair.Sign(map[string]any{"aud": mcpResource, "scope": tk.Remove}, nil))
		if res.Code != 200 {
			t.Fatalf("%s: %d", method, res.Code)
		}
	}
	if len(s.server.bodies) != 5 || len(s.sent()) != 0 {
		t.Fatal("other methods")
	}
}

func TestGETHEADAndDELETEPassAndOtherMethodsGet405(t *testing.T) {
	s := newMCP(t)
	for _, method := range []string{"GET", "HEAD", "DELETE"} {
		if res := s.request(method, "", mcpToken()); res.Code != 200 {
			t.Fatalf("%s: %d", method, res.Code)
		}
	}
	for _, method := range []string{"PUT", "PATCH"} {
		res := s.request(method, call("1", `"delete_all"`), mcpToken())
		if res.Code != 405 || res.Header().Get("Allow") != "GET, POST, DELETE" {
			t.Fatalf("%s: %d %v", method, res.Code, res.Header())
		}
	}
	if res := s.request("OPTIONS", "", ""); res.Code != 200 {
		t.Fatalf("a preflight: %d", res.Code)
	}
}

func TestTheTokenIsCheckedFirst(t *testing.T) {
	s := newMCP(t)
	none := s.request("POST", "{}", "")
	if none.Code != 401 || none.Header().Get("WWW-Authenticate") != s.metadata.Challenge("") {
		t.Fatalf("%d %v", none.Code, none.Header())
	}
	bad := s.request("POST", "{}", "Bearer nope")
	if bad.Code != 401 || bad.Header().Get("WWW-Authenticate") != s.metadata.Challenge("invalid_token") {
		t.Fatalf("%d %v", bad.Code, bad.Header())
	}
	meta := s.request("GET", "", "")
	if meta.Code != 401 {
		t.Fatalf("GET /mcp with no token: %d", meta.Code)
	}
}

func TestOnlyAToolCallTheServerAcceptsIsCounted(t *testing.T) {
	s := newMCP(t)
	s.server.status = 500
	s.post(call("1", `"classify"`))
	s.server.status = 202
	s.post(call("2", `"classify"`))
	s.server.status = 0
	s.server.stream = true
	s.post(call("3", `"classify"`))
	s.server.stream = false
	s.server.silent = true
	s.post(call("4", `"classify"`))
	if got := len(s.sent()); got != 3 {
		t.Fatalf("counted %d, want 3: 202, a stream and an empty 200", got)
	}
}

func TestAnEventStreamIsFlushedThroughTheGuard(t *testing.T) {
	s := newMCP(t)
	s.server.stream = true
	srv := httptest.NewServer(s.handler)
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(call("1", `"classify"`)))
	req.Header.Set("Authorization", mcpToken())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" || string(body) != "event: message\ndata: {}\n\n" {
		t.Fatalf("%d %v %q", res.StatusCode, res.Header, body)
	}
}
