package keelie

// Serve your AI Catalog from your own domain.
//
// The catalog is at /.well-known/ard.json, where ARD v0.91 looks for it, and at
// /.well-known/ai-catalog.json, where the ai-catalog specification looks and an
// MCP proposal points. Both paths serve the same body, from the same copy.
//
// keelie builds the catalog from your published plans. [AICatalog] fetches it
// from keelie with your credential, keeps it for 60 seconds, and serves it with
// no token. A plan you publish shows here within 60 seconds, and within up to
// 120 seconds at a client that caches the answer.
//
// The SDK does not change the document. It keeps no copy past 60 seconds: if
// keelie does not answer when the copy is old, the answer is 503, not an old
// catalog. After a failure, it asks keelie again after 10 seconds, not on each
// request.

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/apiable/keelie-sdk/go/internal/logx"
)

// KeelieCatalogPath is the one place that names keelie's catalog endpoint.
const KeelieCatalogPath = "/ai-catalog"

const (
	// CatalogCacheTime is how long a copy of the catalog is served.
	CatalogCacheTime = 60 * time.Second
	// CatalogRetryTime is how long the SDK waits after a failure before it asks keelie again.
	CatalogRetryTime = 10 * time.Second
)

// CatalogAnswer is what to answer a GET or a HEAD of a catalog path.
type CatalogAnswer struct {
	Status int
	Header http.Header
	Body   []byte
}

// AICatalogOptions are the options of [NewAICatalog]. The zero value is the default.
type AICatalogOptions struct {
	// Clock tells the time. time.Now unless you give another, such as in a test.
	Clock func() time.Time
}

// AICatalog is the catalog, fetched from keelie and kept for 60 seconds. It is
// safe for concurrent use. Serve it with nethttp.AICatalog, or call
// [AICatalog.Answer] from any other server.
type AICatalog struct {
	keelie KeelieClient
	clock  func() time.Time

	mu        sync.Mutex
	body      []byte
	fetchedAt time.Time
	failed    bool
	failedAt  time.Time
	inFlight  *catalogCall
}

type catalogCall struct {
	done chan struct{}
	body []byte
}

// NewAICatalog makes the catalog. keelie carries the auth of a credential that
// may read products, as for the usage reporter. metadata is the one your token
// guard uses: making the catalog with it tells the guards to let a GET or a
// HEAD of the two catalog paths pass with no token. Without it, they guard the
// paths like any other. opts may be nil.
func NewAICatalog(keelie KeelieClient, metadata *ProtectedResourceMetadata, opts *AICatalogOptions) *AICatalog {
	c := &AICatalog{keelie: keelie, clock: time.Now}
	if opts != nil && opts.Clock != nil {
		c.clock = opts.Clock
	}
	metadata.aiCatalog.Store(true)
	return c
}

// Answer is the answer for path, and false if path is not a catalog path. ctx
// bounds the wait for a fetch from keelie, which many requests share.
func (c *AICatalog) Answer(ctx context.Context, path string) (*CatalogAnswer, bool) {
	mediaType, ok := CatalogMediaType(path)
	if !ok {
		return nil, false
	}
	body := c.catalog(ctx)
	if body == nil {
		return &CatalogAnswer{
			Status: http.StatusServiceUnavailable,
			Header: http.Header{"Retry-After": {"10"}, "Cache-Control": {"no-store"}, "Content-Length": {"0"}},
			Body:   []byte{},
		}, true
	}
	return &CatalogAnswer{
		Status: http.StatusOK,
		Header: http.Header{
			"Content-Type":   {mediaType},
			"Cache-Control":  {"max-age=60"},
			"Content-Length": {strconv.Itoa(len(body))},
		},
		Body: body,
	}, true
}

// catalog is the catalog, fetched again when the copy is 60 seconds old. nil
// if keelie fails.
func (c *AICatalog) catalog(ctx context.Context) []byte {
	c.mu.Lock()
	if c.settled() {
		body := c.body
		c.mu.Unlock()
		return body
	}
	// One fetch for many requests at once: the others read what it got, or its failure.
	if c.inFlight == nil {
		c.inFlight = &catalogCall{done: make(chan struct{})}
		c.body = nil
		go c.fetch(c.inFlight)
	}
	call := c.inFlight
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.body
	case <-ctx.Done():
		return nil
	}
}

func (c *AICatalog) fetch(call *catalogCall) {
	body := c.get()
	c.mu.Lock()
	if body == nil {
		c.failed = true
		c.failedAt = c.clock()
	} else {
		c.body = body
		c.fetchedAt = c.clock()
		c.failed = false
	}
	call.body = body
	c.inFlight = nil
	c.mu.Unlock()
	close(call.done)
}

func (c *AICatalog) get() (body []byte) {
	// It runs in a goroutine of its own, so a panic is a failed fetch.
	defer func() {
		if recover() != nil {
			logx.Warn("apiable.catalog_fetch_failed", "error", errorName(errClientPanic))
			body = nil
		}
	}()
	resp, err := sendTo(context.Background(), c.keelie, http.MethodGet, KeelieCatalogPath, nil, nil)
	if err != nil {
		logx.Warn("apiable.catalog_fetch_failed", "error", errorName(err))
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		drain(resp.Body)
		logx.Warn("apiable.catalog_fetch_failed", "status", resp.StatusCode)
		return nil
	}
	body, err = readBody(resp.Body)
	if err != nil {
		logx.Warn("apiable.catalog_fetch_failed", "error", errorName(err))
		return nil
	}
	if body == nil {
		body = []byte{}
	}
	return body
}

// settled is true while the copy is fresh, or while a failure is recent: no fetch is due.
func (c *AICatalog) settled() bool {
	now := c.clock()
	if c.failed {
		return now.Sub(c.failedAt) < CatalogRetryTime
	}
	return c.body != nil && now.Sub(c.fetchedAt) < CatalogCacheTime
}
