package keelie

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	tk "github.com/apiable/keelie-sdk/go/internal/testkit"
)

type sentBatch struct {
	path, key string
	body      string
	events    []map[string]string
}

// fakeKeelie answers each batch with the next answer the test set, and 202
// when none is set. An answer of 0 is a network error.
type fakeKeelie struct {
	mu      sync.Mutex
	sent    []sentBatch
	answers []int
	hang    bool
}

func (f *fakeKeelie) Send(ctx context.Context, method, path string, header http.Header, body []byte) (*http.Response, error) {
	var decoded struct {
		Events []map[string]string `json:"events"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.sent = append(f.sent, sentBatch{path: path, key: header.Get("Idempotency-Key"), body: string(body), events: decoded.Events})
	answer := 202
	if len(f.answers) > 0 {
		answer, f.answers = f.answers[0], f.answers[1:]
	}
	hang := f.hang
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if answer == 0 {
		return nil, errors.New("fetch failed")
	}
	if answer >= 400 {
		return tk.JSON(answer, map[string]any{"type": "https://keelie.example/problems/usage-out-of-range"}), nil
	}
	return tk.JSON(answer, map[string]any{}), nil
}

func (f *fakeKeelie) batches() []sentBatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sent)
}

func (f *fakeKeelie) count() int { return len(f.batches()) }

func until(t *testing.T, check func() bool) {
	t.Helper()
	if err := tk.Until(check); err != nil {
		t.Fatal(err)
	}
}

func newReporter(t *testing.T, k KeelieClient, opts *UsageReporterOptions) *UsageReporter {
	t.Helper()
	r, err := NewUsageReporter(k, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAFullBatchIsSentAtOnceWithOneKeyForTheBatchAndOneForEachEvent(t *testing.T) {
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 3, FlushInterval: time.Minute})
	r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /v1/orders/{orderId}", Credits: "1"})
	r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /v1/orders/{orderId}", Credits: "0.25", ConsumerID: tk.Consumer})
	r.Record(Event{ClientID: "client-b", CapabilityKey: "lookup", Unit: UnitToolCall, Quantity: "2"})
	until(t, func() bool { return keelie.count() == 1 })
	batch := keelie.batches()[0]
	if batch.path != "/usage-events:report" {
		t.Fatal(batch.path)
	}
	if _, ok := parseUUID(batch.key); !ok {
		t.Fatalf("key %q", batch.key)
	}
	if len(batch.events) != 3 {
		t.Fatalf("events %v", batch.events)
	}
	first, second, third := batch.events[0], batch.events[1], batch.events[2]
	if first["credits"] != "1" || first["quantity"] != "1" || first["unit"] != "request" {
		t.Fatalf("first %v", first)
	}
	if _, ok := first["consumer_id"]; ok {
		t.Fatalf("first %v", first)
	}
	if second["credits"] != "0.25" || second["consumer_id"] != tk.Consumer {
		t.Fatalf("second %v", second)
	}
	if _, ok := third["credits"]; ok || third["unit"] != "tool_call" || third["quantity"] != "2" {
		t.Fatalf("third %v", third)
	}
	keys := map[string]bool{}
	for _, e := range batch.events {
		keys[e["idempotency_key"]] = true
	}
	if len(keys) != 3 {
		t.Fatal("one key for each event")
	}
	if _, err := time.Parse("2006-01-02T15:04:05.999999-07:00", first["ts"]); err != nil {
		t.Fatalf("ts %q: %v", first["ts"], err)
	}
	r.Close(context.Background())
}

func TestTheEventsAreWrittenAsPythonWritesThem(t *testing.T) {
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 1, FlushInterval: time.Minute})
	r.Record(Event{ClientID: "clïent", CapabilityKey: `GET /a"b`, Credits: "5", OutcomeID: "job-42", Unit: UnitOutcome, ConsumerID: tk.Consumer})
	until(t, func() bool { return keelie.count() == 1 })
	body := keelie.batches()[0].body
	ts := keelie.batches()[0].events[0]["ts"]
	want := `{"events":[{"idempotency_key":"e13e60df-e85b-588a-a945-f15fed07d021","client_id":"cl` + "\x5c" + `u00efent",` +
		`"capability_key":"GET /a` + "\x5c" + `"b","unit":"outcome","quantity":"1","ts":"` + ts + `","credits":"5",` +
		`"consumer_id":"` + tk.Consumer + `"}]}`
	if body != want {
		t.Fatalf("body\n%s\nwant\n%s", body, want)
	}
	r.Close(context.Background())
}

func TestWhatWaitsIsSentAtEachInterval(t *testing.T) {
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, &UsageReporterOptions{FlushInterval: 20 * time.Millisecond})
	r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /a"})
	until(t, func() bool { return keelie.count() == 1 })
	r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /a"})
	until(t, func() bool { return keelie.count() == 2 })
	r.Close(context.Background())
}

func TestAFailedBatchIsSentAgainWithTheSameKeyAndTheSameBody(t *testing.T) {
	for _, failure := range []int{401, 408, 409, 429, 500, 503, 0} {
		keelie := &fakeKeelie{answers: []int{failure}}
		r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 1, FlushInterval: 20 * time.Millisecond})
		r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /a"})
		until(t, func() bool { return keelie.count() == 2 })
		sent := keelie.batches()
		if sent[0].key != sent[1].key || sent[0].body != sent[1].body {
			t.Fatalf("%d: %v", failure, sent)
		}
		r.Close(context.Background())
	}
}

func TestABatchKeelieRefusesIsDroppedWithTheProblemsCode(t *testing.T) {
	lines := captureLog(t)
	keelie := &fakeKeelie{answers: []int{400}}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 1, FlushInterval: 20 * time.Millisecond})
	r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /a"})
	until(t, func() bool { return keelie.count() == 1 })
	r.Record(Event{ClientID: "client-a", CapabilityKey: "GET /b"})
	until(t, func() bool { return keelie.count() == 2 })
	if got := keelie.batches()[1].events[0]["capability_key"]; got != "GET /b" {
		t.Fatal(got)
	}
	if !lines.Has("apiable.usage_dropped events=1 status=400 type=usage-out-of-range") {
		t.Fatalf("log %q", lines.All())
	}
	r.Close(context.Background())
}

func TestAnEventKeelieWouldRefuseIsLeftOut(t *testing.T) {
	lines := captureLog(t)
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, nil)
	long := make([]rune, 256)
	for i := range long {
		long[i] = 'é'
	}
	for _, e := range []Event{
		{ClientID: "", CapabilityKey: "GET /a"},
		{ClientID: "client", CapabilityKey: string(long)},
		{ClientID: "client", CapabilityKey: "GET /a\n"},
		{ClientID: "client", CapabilityKey: "GET /a\xff"},
		{ClientID: "client", CapabilityKey: "GET /a", Unit: "seconds"},
		{ClientID: "client", CapabilityKey: "GET /a", Quantity: "0"},
		{ClientID: "client", CapabilityKey: "GET /a", Credits: "-1"},
		{ClientID: "client", CapabilityKey: "GET /a", OutcomeID: "job-1"},
		{ClientID: "client", CapabilityKey: "GET /a", Unit: UnitOutcome, Credits: "5"},
		{ClientID: "client", CapabilityKey: "GET /a", ConsumerID: "not-a-uuid"},
	} {
		r.Record(e)
	}
	want := []string{
		"apiable.usage_event_invalid reason=client_id",
		"apiable.usage_event_invalid reason=capability_key",
		"apiable.usage_event_invalid reason=capability_key",
		"apiable.usage_event_invalid reason=capability_key",
		"apiable.usage_event_invalid reason=unit",
		"apiable.usage_event_invalid reason=quantity",
		"apiable.usage_event_invalid reason=credits",
		"apiable.usage_event_invalid reason=outcome_id",
		"apiable.usage_event_invalid reason=outcome_id",
		"apiable.usage_event_invalid reason=consumer_id",
	}
	if !slices.Equal(lines.All(), want) {
		t.Fatalf("log %q", lines.All())
	}
	// 255 characters is the limit, counted as Python counts them.
	r.Record(Event{ClientID: "client", CapabilityKey: string(long[:255]), Unit: UnitOutcome, Credits: "0"})
	r.Close(context.Background())
	if keelie.count() != 1 || len(keelie.batches()[0].events) != 1 {
		t.Fatalf("sent %v", keelie.batches())
	}
}

func TestAnOutcomeIsKeyedAsPythonKeysItSoItIsChargedOnce(t *testing.T) {
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 2, FlushInterval: time.Minute})
	for range 2 {
		r.Record(Event{ClientID: "client", CapabilityKey: "POST /videos", Unit: UnitOutcome, Credits: "50", OutcomeID: "job-42"})
	}
	until(t, func() bool { return keelie.count() == 1 })
	for _, e := range keelie.batches()[0].events {
		// uuid.uuid5(KEELIE_OUTCOME_NAMESPACE, "job-42") in Python.
		if e["idempotency_key"] != "e13e60df-e85b-588a-a945-f15fed07d021" {
			t.Fatal(e["idempotency_key"])
		}
	}
	r.Close(context.Background())
}

func TestTheOldestEventIsDroppedWhenTheBufferIsFull(t *testing.T) {
	lines := captureLog(t)
	keelie := &fakeKeelie{answers: []int{0}}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 1, MaxBufferedEvents: 2, FlushInterval: 50 * time.Millisecond})
	r.Record(Event{ClientID: "client", CapabilityKey: "first"})
	until(t, func() bool { return keelie.count() == 1 }) // fails, and is kept to be sent again
	r.Record(Event{ClientID: "client", CapabilityKey: "second"})
	r.Record(Event{ClientID: "client", CapabilityKey: "third"})
	r.Record(Event{ClientID: "client", CapabilityKey: "fourth"})
	until(t, func() bool { return keelie.count() >= 4 })
	var got []string
	for _, b := range keelie.batches()[:4] {
		got = append(got, b.events[0]["capability_key"])
	}
	if !slices.Equal(got, []string{"first", "first", "third", "fourth"}) {
		t.Fatalf("sent %v", got)
	}
	if !lines.Has("apiable.usage_dropped events=1 reason=buffer_full") {
		t.Fatalf("log %q", lines.All())
	}
	r.Close(context.Background())
}

func TestCloseSendsWhatIsLeftAndRecordsNothingAfter(t *testing.T) {
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, &UsageReporterOptions{FlushInterval: time.Minute})
	r.Record(Event{ClientID: "client", CapabilityKey: "GET /a"})
	r.Record(Event{ClientID: "client", CapabilityKey: "GET /b"})
	r.Close(context.Background())
	if keelie.count() != 1 || len(keelie.batches()[0].events) != 2 {
		t.Fatalf("sent %v", keelie.batches())
	}
	r.Record(Event{ClientID: "client", CapabilityKey: "GET /c"})
	r.Close(context.Background())
	if keelie.count() != 1 {
		t.Fatal("sent after Close")
	}
}

func TestCloseSendsABatchThatWasOnItsWayWithItsKey(t *testing.T) {
	keelie := &fakeKeelie{hang: true}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 1, FlushInterval: time.Minute})
	r.Record(Event{ClientID: "client", CapabilityKey: "GET /a"})
	until(t, func() bool { return keelie.count() == 1 }) // on its way, and never answered
	keelie.mu.Lock()
	keelie.hang = false
	keelie.mu.Unlock()
	r.Close(context.Background())
	sent := keelie.batches()
	if len(sent) != 2 || sent[0].key != sent[1].key || sent[0].body != sent[1].body {
		t.Fatalf("sent %v", sent)
	}
}

func TestCloseGivesUpAfterItsTimeoutAndCountsWhatIsLost(t *testing.T) {
	lines := captureLog(t)
	never := KeelieFunc(func(context.Context, string, string, http.Header, []byte) (*http.Response, error) {
		select {} // a client that never answers, and ignores its context
	})
	r := newReporter(t, never, &UsageReporterOptions{FlushInterval: time.Minute})
	r.Record(Event{ClientID: "client", CapabilityKey: "GET /a"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	r.Close(ctx)
	if time.Since(start) > time.Second {
		t.Fatal("Close waited past its timeout")
	}
	if !lines.Has("apiable.usage_dropped events=1 reason=closed") {
		t.Fatalf("log %q", lines.All())
	}
}

func TestRecordIsSafeFromManyGoroutines(t *testing.T) {
	keelie := &fakeKeelie{}
	r := newReporter(t, keelie, &UsageReporterOptions{BatchSize: 7, FlushInterval: 5 * time.Millisecond})
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				r.Record(Event{ClientID: "client", CapabilityKey: "GET /a"})
			}
		}()
	}
	wg.Wait()
	r.Close(context.Background())
	total := 0
	for _, b := range keelie.batches() {
		total += len(b.events)
	}
	if total != 1000 {
		t.Fatalf("sent %d events", total)
	}
}

func TestTheReporterChecksItsOptions(t *testing.T) {
	for _, opts := range []UsageReporterOptions{
		{BatchSize: -1},
		{BatchSize: 1001},
		{FlushInterval: -time.Second},
		{BatchSize: 10, MaxBufferedEvents: 5},
	} {
		if _, err := NewUsageReporter(&fakeKeelie{}, &opts); err == nil {
			t.Fatalf("%+v: no error", opts)
		}
	}
}

func TestAmountsAreWrittenAsKeelieReadsThem(t *testing.T) {
	for in, want := range map[string]string{
		"1":                 "1",
		"0.25":              "0.25",
		"1.50":              "1.50",
		"001.5":             "1.5",
		"1.5000000":         "1.500000",
		"1000000000":        "1000000000",
		"1000000000.000000": "1000000000.000000",
		"0.000001":          "0.000001",
	} {
		if got, ok := formatAmount(in, true); !ok || got != want {
			t.Errorf("%q: got %q %v", in, got, ok)
		}
	}
	if got, ok := formatAmount("0", false); !ok || got != "0" {
		t.Errorf("0 credits: %q %v", got, ok)
	}
	for _, bad := range []string{"0", "0.0", "-1", "+1", "1e3", "", " 1", "1.", ".5", "0.0000001", "1000000000.000001", "1000000001", "10000000000", "NaN", "١"} {
		if got, ok := formatAmount(bad, true); ok {
			t.Errorf("%q: got %q", bad, got)
		}
	}
}

func TestUUIDsAreReadAndMadeAsPythonReadsAndMakesThem(t *testing.T) {
	for _, form := range []string{
		"{A29FA190-9B27-5A07-A1BA-3A0902A3BDCC}",
		"urn:uuid:a29fa1909b275a07a1ba3a0902a3bdcc",
		"a29f-a1909b275a07a1ba3a0902a3bdcc",
	} {
		if got, ok := parseUUID(form); !ok || got != KeelieOutcomeNamespace {
			t.Errorf("%q: %q", form, got)
		}
	}
	for _, bad := range []string{"a29fa190", "g29fa190-9b27-5a07-a1ba-3a0902a3bdcc", ""} {
		if _, ok := parseUUID(bad); ok {
			t.Errorf("%q read as a UUID", bad)
		}
	}
	// uuid.uuid5 in Python, for the same namespace and names.
	for name, want := range map[string]string{
		"job-42":          "e13e60df-e85b-588a-a945-f15fed07d021",
		"video/7f3a":      "ee03fbee-9a39-53c0-af3a-e31f9479559e",
		"ünïcode-outcome": "5fefc917-f063-5bb9-ac54-a2c331480f03",
	} {
		if got := uuid5(KeelieOutcomeNamespace, name); got != want {
			t.Errorf("%q: %s", name, got)
		}
	}
	if v4 := uuid4(); v4[14] != '4' || v4 == uuid4() {
		t.Error(v4)
	}
}
