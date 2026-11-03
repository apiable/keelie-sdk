package nethttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"

	keelie "github.com/apiable/keelie-sdk/go"
	"github.com/apiable/keelie-sdk/go/internal/logx"
	"github.com/apiable/keelie-sdk/go/internal/pyjson"
	"github.com/apiable/keelie-sdk/go/internal/strictjson"
)

// The method of a tool call. It is also the method half of each key in the
// guard's ScopeMap: "tools/call <tool name>".
const toolsCall = "tools/call"

// MaxBodyBytes is the largest body [MCPGuard] reads, unless you set another.
const MaxBodyBytes = 4 << 20

// JSON-RPC error codes.
const (
	parseError    = -32700
	invalidReq    = -32600
	invalidParams = -32602
	// An application code: MCP keeps -32000 to -32099 for itself.
	insufficientScope = -31001
)

// MCPGuardOptions are the options of [MCPGuard].
type MCPGuardOptions struct {
	Verifier *keelie.TokenVerifier
	Metadata *keelie.ProtectedResourceMetadata
	// Tools maps each tool name to the one scope it requires, such as
	// {"get_order": "orders:read"}. A tool that is not here is refused.
	Tools map[string]string
	// Reporter is the process's one usage reporter.
	Reporter *keelie.UsageReporter
	// MaxBodyBytes is the largest body read. [MaxBodyBytes] when zero.
	MaxBodyBytes int64
}

// MCPGuard checks the token and the tool's scope, and reports each tool call.
//
// Give the MCP endpoint itself as the resource of the metadata: every POST
// under it is read as JSON-RPC. Wrap your MCP server's handler, such as the
// Streamable HTTP handler of github.com/modelcontextprotocol/go-sdk:
//
//	guard, err := nethttp.MCPGuard(nethttp.MCPGuardOptions{
//		Verifier: verifier, Metadata: metadata, Tools: tools, Reporter: reporter,
//	})
//	mux.Handle("/mcp", guard(mcp.NewStreamableHTTPHandler(getServer, nil)))
//
// What it checks on a request whose token verified:
//
//   - A POST body is read in full, up to MaxBodyBytes, and handed on to your
//     server byte for byte. The method and the tool name come from the body
//     only, never from the Mcp-Method or Mcp-Name header.
//   - A tools/call needs the scope you mapped to its tool. A tool that is not
//     in the map is refused. Add every tool that a token may call.
//   - Every other method passes with no scope check: initialize,
//     notifications/*, ping, tools/list, and also resources/* and prompts/*.
//     Apiable sells tools, not resources or prompts.
//   - GET, HEAD and DELETE pass, and so does a CORS preflight (OPTIONS). Every
//     other method gets 405, with Allow: GET, POST, DELETE.
//
// Every refusal is a JSON-RPC error:
//
//   - 400, -32700: the body is not UTF-8 JSON, or it is nested too deeply.
//   - 400, -32600: the body is an array, is not an object, has a key twice, or
//     is a tools/call with no id. A batch is refused on purpose: MCP removed
//     batches in 2025-06-18, so a 2025-03-26 client that batches is cut.
//   - 400, -32602: a tools/call whose params.name is not a string.
//   - 413, -32600: the body is larger than MaxBodyBytes.
//   - 403, -31001, with WWW-Authenticate: Bearer error="insufficient_scope":
//     the token does not carry the tool's scope. The answer does not name the
//     scope, on purpose: an unmapped tool and an unscoped tool look the same,
//     so the answer does not show the map.
//
// The usage event is recorded when your server starts a 2xx response, not at
// the end of its body, so a text/event-stream reply streams through
// unbuffered. The event carries no credits. The claims are in the request's
// context, for [ClaimsFrom].
func MCPGuard(opts MCPGuardOptions) (func(http.Handler) http.Handler, error) {
	if opts.Verifier == nil || opts.Metadata == nil || opts.Reporter == nil {
		return nil, errors.New("keelie: MCPGuard needs a Verifier, a Metadata and a Reporter")
	}
	routes := make(map[string]string, len(opts.Tools))
	for name, scope := range opts.Tools {
		routes[toolsCall+" "+name] = scope
	}
	scopes, err := keelie.NewScopeMap(routes)
	if err != nil {
		return nil, err
	}
	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = MaxBodyBytes
	}
	reporter := opts.Reporter
	scopeRefusal := opts.Metadata.Challenge("insufficient_scope")

	return guard(opts.Verifier, opts.Metadata, func(claims *keelie.Claims, w http.ResponseWriter, r *http.Request, next http.Handler) {
		r = r.WithContext(WithClaims(r.Context(), claims))
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodDelete:
			next.ServeHTTP(w, r)
			return
		case http.MethodPost:
		default:
			// A body under any other method could carry a tool call: refuse it.
			respond(w, r, http.StatusMethodNotAllowed, http.Header{"Allow": {"GET, POST, DELETE"}}, nil)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			// The client went away, or sent a body that does not read.
			respond(w, r, http.StatusBadRequest, nil, nil)
			return
		}
		if int64(len(body)) > maxBody {
			w.Header().Set("Connection", "close")
			rpcError(w, r, http.StatusRequestEntityTooLarge, "null", invalidReq, "Request body too large", "")
			return
		}

		value, err := strictjson.Parse(body)
		if errors.Is(err, strictjson.ErrDuplicateKey) {
			rpcError(w, r, http.StatusBadRequest, "null", invalidReq, "Invalid Request", "")
			return
		} else if err != nil {
			rpcError(w, r, http.StatusBadRequest, "null", parseError, "Parse error", "")
			return
		}
		request, ok := value.(map[string]any)
		if !ok {
			rpcError(w, r, http.StatusBadRequest, "null", invalidReq, "Invalid Request", "")
			return
		}

		tool := ""
		if request["method"] == toolsCall {
			id, ok := requestID(request["id"])
			if !ok {
				rpcError(w, r, http.StatusBadRequest, "null", invalidReq, "Invalid Request", "")
				return
			}
			params, _ := request["params"].(map[string]any)
			name, ok := params["name"].(string)
			if !ok {
				rpcError(w, r, http.StatusBadRequest, id, invalidParams, "Invalid params", "")
				return
			}
			if scopes.Check(claims, toolsCall, name) != nil {
				rpcError(w, r, http.StatusForbidden, id, insufficientScope, "Insufficient scope", scopeRefusal)
				return
			}
			tool = name
		}

		// The server reads the body that was checked, byte for byte.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		if tool == "" {
			next.ServeHTTP(w, r)
			return
		}
		counted := &countingWriter{ResponseWriter: w, record: func() {
			reporter.Record(keelie.Event{
				ClientID:      claims.AZP,
				CapabilityKey: tool,
				Unit:          keelie.UnitToolCall,
				ConsumerID:    claims.ConsumerID,
			})
		}}
		next.ServeHTTP(counted, r)
		// A handler that writes nothing answers 200.
		counted.start(http.StatusOK)
	})
}

// requestID is the JSON of a tool call's id: a string or an integer, never a
// boolean, a fraction or null.
func requestID(id any) (string, bool) {
	switch v := id.(type) {
	case string:
		var b bytes.Buffer
		pyjson.String(&b, v)
		return b.String(), true
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return "", false
		}
		n, ok := new(big.Int).SetString(string(v), 10)
		if !ok {
			return "", false
		}
		return n.String(), true
	}
	return "", false
}

// rpcError answers with a JSON-RPC error. id is the request's id as JSON.
func rpcError(w http.ResponseWriter, r *http.Request, status int, id string, code int, message, challenge string) {
	logx.Info("apiable.mcp_refused", "status", status, "code", code)
	var b bytes.Buffer
	b.WriteString(`{"jsonrpc":"2.0","id":`)
	b.WriteString(id)
	b.WriteString(`,"error":{"code":`)
	pyjson.Int(&b, code)
	b.WriteString(`,"message":`)
	pyjson.String(&b, message)
	b.WriteString(`}}`)
	header := http.Header{"Content-Type": {"application/json"}}
	if challenge != "" {
		header.Set("WWW-Authenticate", challenge)
	}
	respond(w, r, status, header, b.Bytes())
}

// countingWriter records one event when the response starts with 2xx.
type countingWriter struct {
	http.ResponseWriter
	record func()
	seen   bool
}

func (c *countingWriter) start(status int) {
	if c.seen {
		return
	}
	c.seen = true
	if status >= 200 && status <= 299 {
		c.record()
	}
}

func (c *countingWriter) WriteHeader(status int) {
	// An informational answer, such as 103, comes before the response's own status.
	if status >= 200 {
		c.start(status)
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.start(http.StatusOK)
	return c.ResponseWriter.Write(b)
}

// Flush sends what is written so far, so that an event stream is not buffered.
func (c *countingWriter) Flush() {
	c.start(http.StatusOK)
	_ = http.NewResponseController(c.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the writer underneath.
func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }
