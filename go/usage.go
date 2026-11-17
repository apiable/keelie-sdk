package keelie

// Report usage to keelie in batches, off the request path.
//
// [UsageReporter.Record] puts one event in a buffer in memory and returns. It
// does no I/O and never waits on the network, so it adds no time to the request
// that calls it. A goroutine sends the buffer to keelie's usage endpoint: when
// it holds a full batch, and at each interval. The interval is 5 seconds unless
// you set another.
//
// What the SDK reports is telemetry. It feeds the Provider's dashboards and the
// Consumer's spend cap. Apiable never puts it on an invoice.
//
// Each event carries its own idempotency key, and each batch carries an
// Idempotency-Key. A batch that fails on the way is sent again later with the
// same key and the same body, so keelie keeps each event once.
//
// A token for a person names its Consumer in consumer_id: its azp is an agent's
// client, which serves every Consumer. Pass claims.ConsumerID with each event.
// keelie then burns that Consumer's credits. On a credential's token it is "",
// and nothing is sent.
//
// An outcome is charged once. An event with Unit "outcome" and an OutcomeID
// takes its key from the outcome ID, with [KeelieOutcomeNamespace]. The same
// outcome then has the same key on every repeat, in every process and in every
// language, and keelie keeps the key in every month. A repeat burns nothing.
//
// A report that fails never stops a request:
//
//   - A network error, a 401, 408, 409, 429 or a 5xx keeps the batch. The
//     reporter sends it again after one interval. It does not read Retry-After.
//   - Any other answer drops the batch, with a log line. A retry gets the same
//     answer. usage-out-of-range is one of these: the batch would take a
//     counter or a balance past the largest value keelie keeps.
//   - When the buffer is full, the oldest event goes, and a log line counts it.
//
// keelie refuses an event older than the start of the previous month. After an
// outage that long, a batch that holds such an event is dropped.
//
// Nothing is written to disk. [UsageReporter.Close] sends what is left at
// shutdown. Events it cannot send in time are lost, with a log line.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/apiable/keelie-sdk/go/internal/logx"
	"github.com/apiable/keelie-sdk/go/internal/pyjson"
)

// UsagePath is the one place that names keelie's usage endpoint.
const UsagePath = "/usage-events:report"

// The units of a usage event.
const (
	UnitRequest  = "request"
	UnitToolCall = "tool_call"
	UnitToken    = "token"
	UnitOutcome  = "outcome"
)

// KeelieOutcomeNamespace is the namespace of an outcome's key:
// uuid5(KeelieOutcomeNamespace, outcomeID). Fixed for good, and the same in
// every language. A UUIDv5 and not a random key: the key must be the same on
// every repeat of the outcome, so that keelie charges it once.
const KeelieOutcomeNamespace = "a29fa190-9b27-5a07-a1ba-3a0902a3bdcc"

// What keelie takes in one event, and in one batch.
const (
	MaxNameLength      = 255
	MaxBatchSize       = 1000
	BatchSize          = 50
	MaxBufferedEvents  = 10_000
	maxAmountDigits    = 10 // 10 ** 9, the largest amount, has ten digits
	places             = 6
	defaultCloseWindow = 10 * time.Second
)

// FlushInterval is at most 5 seconds. A Consumer's balance may go below zero
// for 60 seconds at most, and that window must hold one flush, one failed
// flush, a retry and a burst.
const FlushInterval = 5 * time.Second

var (
	control     = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	problemCode = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	amountForm  = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?$`)
	nonZero     = regexp.MustCompile(`[1-9]`)
)

// Event is one usage event. Only ClientID and CapabilityKey are required.
type Event struct {
	// ClientID is claims.AZP: the Consumer's credential, or the agent's client
	// on a token for a person.
	ClientID string
	// CapabilityKey names the route or the tool that was called, such as
	// "GET /v1/orders/{orderId}". 255 characters at most.
	CapabilityKey string
	// Unit is UnitRequest when empty, or UnitToolCall, UnitToken or UnitOutcome.
	Unit string
	// Quantity is how many units, "1" when empty. An amount is a decimal
	// string such as "2" or "0.25": no sign, at most six places, at most
	// 1000000000.
	Quantity string
	// Credits is what the call costs the Consumer's balance, as an amount.
	// Leave it empty when the call is free.
	Credits string
	// OutcomeID names the outcome of a UnitOutcome event, such as the ID of the
	// job. It must be unique across all your Consumers. The event's key is made
	// from it, so keelie charges the outcome once, however often it is
	// reported. An outcome with credits needs it. Any other unit must not have it.
	OutcomeID string
	// ConsumerID is claims.ConsumerID: the Consumer of a token for a person,
	// whose credits the call burns. Always pass it. It is "" on a credential's
	// token: keelie refuses a consumer_id there. keelie refuses a batch with an
	// event of an agent's client that has no consumer_id.
	ConsumerID string
}

// UsageReporterOptions are the options of [NewUsageReporter]. The zero value is the default.
type UsageReporterOptions struct {
	// BatchSize is the number of events in one batch, from 1 to 1000. 50 when zero.
	BatchSize int
	// FlushInterval is how often the reporter sends what waits. 5 seconds when
	// zero. Keep it at 5 seconds or less.
	FlushInterval time.Duration
	// MaxBufferedEvents is how many events wait in memory. 10,000 when zero.
	MaxBufferedEvents int
}

type batch struct {
	key   string
	body  []byte
	count int
}

// UsageReporter collects usage events and sends them to keelie in batches, in
// the background. It is safe for concurrent use. Make one for the process, and
// call [UsageReporter.Close] when the process shuts down.
type UsageReporter struct {
	keelie    KeelieClient
	batchSize int
	interval  time.Duration
	max       int

	mu      sync.Mutex
	events  [][]byte // each event's JSON, in order
	dropped int
	closed  bool
	started bool
	// pending is the batch on its way, kept as sent: a retry repeats its key and
	// its body.
	pending *batch

	wake    chan struct{}
	stop    context.CancelFunc
	stopped context.Context
	done    chan struct{}
}

// NewUsageReporter makes the reporter. keelie sends a request to keelie with
// the auth of a credential that may report usage: use [NewSDKCredential]. opts
// may be nil. It is an error when an option is out of range.
func NewUsageReporter(keelie KeelieClient, opts *UsageReporterOptions) (*UsageReporter, error) {
	r := &UsageReporter{keelie: keelie, batchSize: BatchSize, interval: FlushInterval, max: MaxBufferedEvents}
	if opts != nil {
		if opts.BatchSize != 0 {
			r.batchSize = opts.BatchSize
		}
		if opts.FlushInterval != 0 {
			r.interval = opts.FlushInterval
		}
		if opts.MaxBufferedEvents != 0 {
			r.max = opts.MaxBufferedEvents
		}
	}
	if r.batchSize < 1 || r.batchSize > MaxBatchSize {
		return nil, fmt.Errorf("keelie: BatchSize must be from 1 to %d", MaxBatchSize)
	}
	if r.interval <= 0 {
		return nil, errors.New("keelie: FlushInterval must be more than 0")
	}
	if r.max < r.batchSize {
		return nil, errors.New("keelie: MaxBufferedEvents must be at least BatchSize")
	}
	r.wake = make(chan struct{}, 1)
	r.done = make(chan struct{})
	r.stopped, r.stop = context.WithCancel(context.Background())
	return r, nil
}

// Record puts one event in the buffer, and returns at once.
//
// It never fails and never waits on the network. An event keelie would refuse
// is logged and left out, so it cannot cost the other events of its batch.
func (r *UsageReporter) Record(e Event) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return
	}
	unit := e.Unit
	if unit == "" {
		unit = UnitRequest
	}
	quantity := e.Quantity
	if quantity == "" {
		quantity = "1"
	}
	amount, amountOK := formatAmount(quantity, true)
	cost, costOK := "", true
	if e.Credits != "" {
		cost, costOK = formatAmount(e.Credits, false)
	}
	consumer, consumerOK := "", true
	if e.ConsumerID != "" {
		consumer, consumerOK = parseUUID(e.ConsumerID)
	}
	reason := ""
	switch {
	case !nameOK(e.ClientID):
		reason = "client_id"
	case !nameOK(e.CapabilityKey):
		reason = "capability_key"
	case unit != UnitRequest && unit != UnitToolCall && unit != UnitToken && unit != UnitOutcome:
		reason = "unit"
	case !amountOK:
		reason = "quantity"
	case !costOK:
		reason = "credits"
	case e.OutcomeID != "" && (unit != UnitOutcome || !nameOK(e.OutcomeID)):
		reason = "outcome_id"
	case e.OutcomeID == "" && unit == UnitOutcome && nonZero.MatchString(cost):
		// Without the ID, each repeat of the outcome would burn the balance again.
		reason = "outcome_id"
	case !consumerOK:
		reason = "consumer_id"
	}
	if reason != "" {
		// A fixed word: the value can come from the request, and stays out of the log.
		logx.Warn("apiable.usage_event_invalid", "reason", reason)
		return
	}
	key := uuid4()
	if e.OutcomeID != "" {
		key = uuid5(KeelieOutcomeNamespace, e.OutcomeID)
	}
	pairs := []string{
		"idempotency_key", key,
		"client_id", e.ClientID,
		"capability_key", e.CapabilityKey,
		"unit", unit,
		"quantity", amount,
		"ts", isoNow(),
	}
	if e.Credits != "" {
		pairs = append(pairs, "credits", cost)
	}
	if consumer != "" {
		pairs = append(pairs, "consumer_id", consumer)
	}
	var b bytes.Buffer
	pyjson.Object(&b, pairs...)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	if len(r.events) >= r.max {
		// The oldest event goes to take this one.
		r.events = r.events[1:]
		r.dropped++
	}
	r.events = append(r.events, b.Bytes())
	full := len(r.events) >= r.batchSize
	r.startLocked()
	r.mu.Unlock()
	if full {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

// Start starts the goroutine that sends the events. Record starts it too; this
// is for a process that wants it running first.
func (r *UsageReporter) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.startLocked()
	}
}

func (r *UsageReporter) startLocked() {
	if !r.started {
		r.started = true
		go r.run()
	}
}

// Close stops the goroutine, and sends what is in the buffer, once. It gives
// up when ctx is done, or after 10 seconds if ctx has no deadline. What it does
// not send is lost, with one log line. Record does nothing after Close.
func (r *UsageReporter) Close(ctx context.Context) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	started := r.started
	r.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCloseWindow)
		defer cancel()
	}
	// Stopping the goroutine cancels a batch on its way. It stays pending, and
	// goes first below, with the same key.
	r.stop()
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		if started {
			<-r.done
		}
		r.safeFlush(ctx)
	}()
	select {
	case <-flushed:
	case <-ctx.Done():
	}
	r.mu.Lock()
	lost := len(r.events)
	if r.pending != nil {
		lost += r.pending.count
	}
	r.mu.Unlock()
	if lost > 0 {
		logx.Warn("apiable.usage_dropped", "events", lost, "reason", "closed")
	}
}

func (r *UsageReporter) run() {
	defer close(r.done)
	retry := false
	for {
		if !retry {
			select {
			case <-r.wake:
			case <-time.After(r.interval):
			case <-r.stopped.Done():
				return
			}
		}
		select {
		case <-r.wake:
		default:
		}
		retry = !r.safeFlush(r.stopped)
		if r.stopped.Err() != nil {
			return
		}
		if retry {
			// keelie or the network failed. Wait one interval, whatever fills
			// the buffer, then send the same batch again.
			select {
			case <-time.After(r.interval):
			case <-r.stopped.Done():
				return
			}
		}
	}
}

// safeFlush is flush, run where a panic would stop the process: the reporter's
// goroutine, and Close's. A panic is a failed send. The batch on its way stays
// pending, and is sent again with the same key.
func (r *UsageReporter) safeFlush(ctx context.Context) (ok bool) {
	defer func() {
		if recover() != nil {
			logx.Warn("apiable.usage_not_sent", "error", errorName(errClientPanic))
			ok = false
		}
	}()
	return r.flush(ctx)
}

// flush sends every batch in the buffer. It is false if a batch must be sent
// again later. One flush runs at a time: the goroutine's, then Close's.
func (r *UsageReporter) flush(ctx context.Context) bool {
	defer r.logDropped()
	for {
		r.mu.Lock()
		if r.pending == nil {
			r.pending = r.nextBatchLocked()
		}
		b := r.pending
		r.mu.Unlock()
		if b == nil {
			return true
		}
		if ctx.Err() != nil || !r.send(ctx, b) {
			return false
		}
		r.mu.Lock()
		r.pending = nil
		r.mu.Unlock()
	}
}

func (r *UsageReporter) nextBatchLocked() *batch {
	n := min(len(r.events), r.batchSize)
	if n == 0 {
		return nil
	}
	events := r.events[:n]
	r.events = r.events[n:]
	var b bytes.Buffer
	b.WriteString(`{"events":[`)
	b.Write(bytes.Join(events, []byte(",")))
	b.WriteString(`]}`)
	return &batch{key: uuid4(), body: b.Bytes(), count: n}
}

// send sends one batch. It is true when the batch is done with: kept by keelie, or dropped.
func (r *UsageReporter) send(ctx context.Context, b *batch) bool {
	header := http.Header{"Content-Type": {"application/json"}, "Idempotency-Key": {b.key}}
	resp, err := sendTo(ctx, r.keelie, http.MethodPost, UsagePath, header, b.body)
	if err != nil {
		logx.Warn("apiable.usage_not_sent", "events", b.count, "error", errorName(err))
		return false
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	if status >= 200 && status <= 299 {
		drain(resp.Body)
		logx.Debug("apiable.usage_sent", "events", b.count)
		return true
	}
	if status == 401 || status == 408 || status == 409 || status == 429 || status >= 500 {
		drain(resp.Body)
		logx.Warn("apiable.usage_not_sent", "events", b.count, "status", status)
		return false
	}
	logx.Warn("apiable.usage_dropped", "events", b.count, "status", status, "type", problemType(resp.Body))
	return true
}

func (r *UsageReporter) logDropped() {
	r.mu.Lock()
	dropped := r.dropped
	r.dropped = 0
	r.mu.Unlock()
	if dropped > 0 {
		logx.Warn("apiable.usage_dropped", "events", dropped, "reason", "buffer_full")
	}
}

func nameOK(name string) bool {
	return name != "" && utf8.ValidString(name) && utf8.RuneCountInString(name) <= MaxNameLength &&
		!control.MatchString(name)
}

// formatAmount is the amount as keelie reads it, a plain decimal string with no
// sign and at most six places, and false if keelie would refuse it.
func formatAmount(value string, positive bool) (string, bool) {
	match := amountForm.FindStringSubmatch(value)
	if match == nil {
		return "", false
	}
	whole := strings.TrimLeft(match[1], "0")
	if whole == "" {
		whole = "0"
	}
	fraction := match[2]
	// Zeros past the sixth place change nothing, and keelie reads six at most.
	if len(fraction) > places {
		if nonZero.MatchString(fraction[places:]) {
			return "", false
		}
		fraction = fraction[:places]
	}
	if len(whole) > maxAmountDigits {
		return "", false
	}
	if len(whole) == maxAmountDigits && (whole != "1000000000" || nonZero.MatchString(fraction)) {
		return "", false
	}
	if positive && !nonZero.MatchString(whole+fraction) {
		return "", false
	}
	if match[2] == "" {
		return whole, true
	}
	return whole + "." + fraction, true
}

// isoNow is the time as Python's datetime.now(timezone.utc).isoformat() writes it.
func isoNow() string {
	now := time.Now().UTC()
	if now.Nanosecond()/1000 == 0 {
		return now.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return now.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

// problemType is the last segment of the problem's type, such as usage-out-of-range.
func problemType(body io.Reader) string {
	var problem map[string]any
	if json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&problem) != nil {
		return "unknown"
	}
	kind, ok := problem["type"].(string)
	if !ok {
		return "unknown"
	}
	kind = strings.TrimRight(kind, "/")
	code := kind[strings.LastIndexByte(kind, '/')+1:]
	// keelie's codes are short and plain. Anything else stays out of the log.
	if !problemCode.MatchString(code) {
		return "unknown"
	}
	return code
}
