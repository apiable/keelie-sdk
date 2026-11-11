// Package logx holds the logger every package of the SDK writes to.
//
// Each line is one fixed event name, such as apiable.token_rejected, with its
// fields as attributes. The names are the Python SDK's, so one search finds an
// event in every language. No line holds a token, a secret or a value taken
// from the request.
package logx

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

// quiet writes warnings to stderr, and drops info and debug.
var quiet = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

var current atomic.Pointer[slog.Logger]

func init() { current.Store(quiet) }

// Set sends the SDK's lines to logger. nil restores the default.
func Set(logger *slog.Logger) {
	if logger == nil {
		logger = quiet
	}
	current.Store(logger)
}

// Debug writes one debug line.
func Debug(event string, args ...any) { log(slog.LevelDebug, event, args) }

// Info writes one info line.
func Info(event string, args ...any) { log(slog.LevelInfo, event, args) }

// Warn writes one warning.
func Warn(event string, args ...any) { log(slog.LevelWarn, event, args) }

func log(level slog.Level, event string, args []any) {
	current.Load().Log(context.Background(), level, event, args...)
}
