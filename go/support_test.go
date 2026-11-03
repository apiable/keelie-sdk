package keelie

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestMain(m *testing.M) {
	// The tests read the lines they expect with captureLog. The rest stay quiet.
	SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// logLines collects each line as "event key=value ...", in the order written.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) Enabled(context.Context, slog.Level) bool { return true }

func (l *logLines) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	l.mu.Lock()
	l.lines = append(l.lines, b.String())
	l.mu.Unlock()
	return nil
}

func (l *logLines) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logLines) WithGroup(string) slog.Handler      { return l }

// Has is true when line was written.
func (l *logLines) Has(line string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, got := range l.lines {
		if got == line {
			return true
		}
	}
	return false
}

// All is every line so far.
func (l *logLines) All() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// captureLog sends the SDK's lines to a list until the test ends.
func captureLog(t *testing.T) *logLines {
	lines := &logLines{}
	SetLogger(slog.New(lines))
	t.Cleanup(func() { SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil))) })
	return lines
}
