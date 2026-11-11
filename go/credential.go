package keelie

// Talk to keelie with your SDK credential.
//
// The usage reporter and the AI Catalog call keelie's API. Each call carries a
// token of the sdk_credential from your signup: it may report usage and read
// your products, and nothing else. [NewSDKCredential] mints that token at your
// issuer with the client credentials grant, keeps it until shortly before it
// expires, and mints again on a 401.
//
// The SDK holds no secret of its own. Read the client id and the secret from the
// environment, never from source code. Never give it your admin credential.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KeelieClient sends one request to keelie's API, with the auth of a
// credential. path is keelie's path, such as /usage-events:report; the base URL
// and the auth are the client's own. The caller closes the response body.
//
// [NewSDKCredential] makes one. A test can give a [KeelieFunc].
type KeelieClient interface {
	Send(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error)
}

// KeelieFunc is a function that is a [KeelieClient].
type KeelieFunc func(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error)

// Send calls f.
func (f KeelieFunc) Send(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error) {
	return f(ctx, method, path, header, body)
}

// SDKCredentialTimeout is how long a call to keelie, or to the token endpoint,
// may take unless you set another.
const SDKCredentialTimeout = 10 * time.Second

// SDKCredentialOptions are the options of [NewSDKCredential].
type SDKCredentialOptions struct {
	// KeelieURL is the address of keelie: KEELIE_URL.
	KeelieURL string
	// TokenURL is the token endpoint of keelie's issuer: KEELIE_TOKEN_URL.
	TokenURL string
	// ClientID is sdk_credential.client_id from the signup answer.
	ClientID string
	// ClientSecret is sdk_credential.client_secret from the signup answer.
	ClientSecret string
	// Timeout bounds a call that has no deadline of its own.
	// [SDKCredentialTimeout] when zero.
	Timeout time.Duration
	// HTTPClient sends the requests. The SDK sends with a copy of it that
	// follows no redirect, whatever its CheckRedirect: a 307 or 308 of the
	// token request would send the client secret on to the new address. The
	// client you give is not changed. By default a new http.Client.
	HTTPClient *http.Client
}

// SDKCredential is a [KeelieClient] that sends a token of your SDK credential
// with each request. It is safe for concurrent use.
type SDKCredential struct {
	base    string
	token   string // the token endpoint
	form    string
	timeout time.Duration
	client  *http.Client

	mu        sync.Mutex
	access    string
	expiresAt time.Time
	minting   *mintCall
}

type mintCall struct {
	done chan struct{}
	err  error
}

// NewSDKCredential makes the client. KeelieURL, TokenURL, ClientID and
// ClientSecret are required.
func NewSDKCredential(opts SDKCredentialOptions) (*SDKCredential, error) {
	if opts.KeelieURL == "" || opts.TokenURL == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		return nil, errors.New("keelie: KeelieURL, TokenURL, ClientID and ClientSecret are required")
	}
	c := &SDKCredential{
		base:    strings.TrimRight(opts.KeelieURL, "/"),
		token:   opts.TokenURL,
		timeout: opts.Timeout,
		client:  &http.Client{},
		// The order of Python's and Node's form, so that the two read the same.
		form: "grant_type=client_credentials&client_id=" + url.QueryEscape(opts.ClientID) +
			"&client_secret=" + url.QueryEscape(opts.ClientSecret),
	}
	if c.timeout <= 0 {
		c.timeout = SDKCredentialTimeout
	}
	if opts.HTTPClient != nil {
		// A copy: the client is the caller's, and may send other requests.
		*c.client = *opts.HTTPClient
	}
	c.client.CheckRedirect = noRedirect
	return c, nil
}

// Send sends one request to keelie with a fresh token. On a 401 it mints a new
// token and sends the request once more.
func (c *SDKCredential) Send(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		resp, err := c.send(ctx, method, path, header, body)
		if err != nil {
			cancel()
			return nil, err
		}
		resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	return c.send(ctx, method, path, header, body)
}

func (c *SDKCredential) send(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error) {
	token, err := c.fresh(ctx, false, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.request(ctx, method, path, header, body, token)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	drain(resp.Body)
	resp.Body.Close()
	if token, err = c.fresh(ctx, true, token); err != nil {
		return nil, err
	}
	return c.request(ctx, method, path, header, body, token)
}

func (c *SDKCredential) request(ctx context.Context, method, path string, header http.Header, body []byte, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, values := range header {
		req.Header[name] = append([]string(nil), values...)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return do(c.client, req)
}

// fresh gives a token that has not expired. With force, it mints a new one,
// unless another caller already replaced the token that was refused. Every
// caller waits on the same mint.
func (c *SDKCredential) fresh(ctx context.Context, force bool, refused string) (string, error) {
	c.mu.Lock()
	stale := c.access == "" || (force && c.access == refused) || !time.Now().Before(c.expiresAt)
	if c.minting == nil && stale {
		c.minting = &mintCall{done: make(chan struct{})}
		// The mint runs on its own, so that a caller that goes away does not
		// fail it for the others.
		go c.mint(c.minting)
	}
	call := c.minting
	token := c.access
	c.mu.Unlock()
	if call == nil {
		return token, nil
	}
	select {
	case <-call.done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if call.err != nil {
		return "", call.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.access, nil
}

func (c *SDKCredential) mint(call *mintCall) {
	token, lifetime, err := c.safeMintToken()
	c.mu.Lock()
	if err == nil {
		c.access = token
		// Mint again before the token expires.
		c.expiresAt = time.Now().Add(time.Duration(max(lifetime-30, lifetime/2) * float64(time.Second)))
	}
	call.err = err
	c.minting = nil
	c.mu.Unlock()
	close(call.done)
}

// safeMintToken is mintToken, with a panic as an error: every caller waits on
// the mint, and it runs in a goroutine of its own.
func (c *SDKCredential) safeMintToken() (token string, lifetime float64, err error) {
	defer func() {
		if recover() != nil {
			token, lifetime, err = "", 0, errClientPanic
		}
	}()
	return c.mintToken()
}

func (c *SDKCredential) mintToken() (string, float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.token, strings.NewReader(c.form))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := do(c.client, req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		drain(resp.Body)
		return "", 0, fmt.Errorf("keelie: the token endpoint answered %d", resp.StatusCode)
	}
	body, err := readBody(resp.Body)
	if err != nil {
		return "", 0, err
	}
	var answer struct {
		AccessToken *string  `json:"access_token"`
		ExpiresIn   *float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.AccessToken == nil || answer.ExpiresIn == nil {
		return "", 0, errors.New("keelie: the token endpoint answered without a token")
	}
	return *answer.AccessToken, *answer.ExpiresIn, nil
}

// cancelOnClose ends the call's own timeout when the body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
