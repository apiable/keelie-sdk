package keelie

// Every request the SDK sends goes through do or sendTo, and every body it reads
// through readBody or drain.
//
// The client is yours to give: an *http.Client with your own RoundTripper, or a
// KeelieClient. A client that panics, or that answers with neither a response
// nor an error, must not stop your process: the SDK's requests run in its own
// goroutines, where nothing above would catch it. Each is an error instead,
// with a fixed word in the log. A body is read up to maxResponseBytes; a longer
// one is an error, so an issuer or a proxy that answers without end cannot fill
// your memory.

import (
	"context"
	"io"
	"net/http"
)

// maxResponseBytes is the most the SDK reads of one response body: the
// issuer's discovery document and key set, a token, keelie's catalog.
const maxResponseBytes = 1 << 20

var (
	errClientPanic = &fetchError{"client_panic"}
	errNoResponse  = &fetchError{"no_response"}
	errTooLarge    = &fetchError{"too_large"}
)

// do sends req with client.
func do(client *http.Client, req *http.Request) (resp *http.Response, err error) {
	defer func() {
		if recover() != nil {
			resp, err = nil, errClientPanic
		}
	}()
	return checked(client.Do(req))
}

// sendTo sends one request to keelie with k.
func sendTo(ctx context.Context, k KeelieClient, method, path string, header http.Header, body []byte) (resp *http.Response, err error) {
	defer func() {
		if recover() != nil {
			resp, err = nil, errClientPanic
		}
	}()
	return checked(k.Send(ctx, method, path, header, body))
}

// checked is an error for a response that is not there, and gives a response
// with no body an empty one.
func checked(resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	if resp == nil {
		return nil, errNoResponse
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	return resp, nil
}

// readBody reads all of body, and is an error past maxResponseBytes.
func readBody(body io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponseBytes {
		return nil, errTooLarge
	}
	return b, nil
}

// drain reads what is left of a body the SDK does not need, up to
// maxResponseBytes, so that the connection can be used again.
func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxResponseBytes))
}

// noRedirect is the CheckRedirect of every client the SDK sends to keelie or
// its issuer with: the 3xx itself is the answer.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
