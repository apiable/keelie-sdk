// Package keelie is the Keelie SDK, by Apiable. In development, not released.
//
// Source: https://github.com/apiable/keelie-sdk
//
// It verifies tokens inside your own process, against the issuer's key set,
// which it fetches and caches, and checks their scope against the route. It
// reports usage in batches, in the background. It does not sit in the request
// path. It serves the RFC 9728 metadata that tells an agent where to get a
// token, and your AI Catalog, which keelie builds from your published plans.
//
// This package is the core, with no framework in it. The net/http middleware,
// for a REST API and for an MCP server, is in the package
// github.com/apiable/keelie-sdk/go/nethttp.
package keelie

import (
	"log/slog"

	"github.com/apiable/keelie-sdk/go/internal/logx"
)

// Version is the version of the SDK.
const Version = "0.0.1"

// SetLogger sends the SDK's log lines to logger. Give nil for the default.
//
// Each line is one fixed event name, such as apiable.token_rejected, with its
// fields as attributes. The names are the Python SDK's. No line holds a token,
// a secret or a value taken from the request.
//
// By default warnings go to stderr, and info and debug lines are dropped.
func SetLogger(logger *slog.Logger) {
	logx.Set(logger)
}
