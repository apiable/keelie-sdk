import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { KeelieFetch } from "../src/credential.js";
import { setLogger } from "../src/log.js";
import { KEELIE_OUTCOME_NAMESPACE, UsageReporter, formatAmount } from "../src/usage.js";
import { parseUuid, uuid5 } from "../src/uuid.js";
import { CONSUMER, until } from "./support.js";

type Sent = { path: string; key: string; events: Record<string, string>[] };

/** A keelie whose next answers the test sets. It answers 202 when none is set. */
function fakeKeelie() {
  const sent: Sent[] = [];
  const answers: (number | "network")[] = [];
  const keelie: KeelieFetch = async (path, init) => {
    const headers = new Headers(init?.headers);
    sent.push({
      path,
      key: headers.get("Idempotency-Key") ?? "",
      events: (JSON.parse(String(init?.body)) as { events: Record<string, string>[] }).events,
    });
    const answer = answers.shift() ?? 202;
    if (answer === "network") throw new TypeError("fetch failed");
    return Response.json(answer >= 400 ? { type: "https://keelie.example/problems/usage-out-of-range" } : {}, {
      status: answer,
    });
  };
  return { keelie, sent, answers };
}

function captureLog() {
  const lines: string[] = [];
  setLogger({ debug() {}, info: (m) => lines.push(m), warn: (m) => lines.push(m) });
  return lines;
}

describe("UsageReporter", () => {
  it("sends a full batch at once, with one key for the batch and one for each event", async () => {
    const { keelie, sent } = fakeKeelie();
    const reporter = new UsageReporter(keelie, { batchSize: 3, flushIntervalSeconds: 60 });
    reporter.record("client-a", "GET /v1/orders/:orderId", { credits: 1 });
    reporter.record("client-a", "GET /v1/orders/:orderId", { credits: "0.25", consumerId: CONSUMER });
    reporter.record("client-b", "lookup", { unit: "tool_call", quantity: 2 });
    await until(() => sent.length === 1);
    const [batch] = sent;
    assert.equal(batch!.path, "/usage-events:report");
    assert.ok(parseUuid(batch!.key));
    assert.equal(batch!.events.length, 3);
    const [first, second, third] = batch!.events;
    assert.equal(first!["credits"], "1");
    assert.equal(first!["quantity"], "1");
    assert.equal(first!["unit"], "request");
    assert.equal(first!["consumer_id"], undefined);
    assert.equal(second!["credits"], "0.25");
    assert.equal(second!["consumer_id"], CONSUMER);
    assert.equal(third!["unit"], "tool_call");
    assert.equal(third!["quantity"], "2");
    assert.equal(third!["credits"], undefined);
    assert.equal(new Set(batch!.events.map((e) => e["idempotency_key"])).size, 3);
    assert.ok(!Number.isNaN(Date.parse(first!["ts"]!)));
    await reporter.close();
  });

  it("sends what it holds at each interval", async () => {
    const { keelie, sent } = fakeKeelie();
    const reporter = new UsageReporter(keelie, { flushIntervalSeconds: 0.02 });
    reporter.record("client-a", "GET /a");
    await until(() => sent.length === 1);
    reporter.record("client-a", "GET /a");
    await until(() => sent.length === 2);
    await reporter.close();
  });

  it("sends a failed batch again with the same key and the same body", async () => {
    for (const failure of [401, 408, 409, 429, 500, 503, "network"] as const) {
      const { keelie, sent, answers } = fakeKeelie();
      captureLog();
      answers.push(failure);
      const reporter = new UsageReporter(keelie, { batchSize: 1, flushIntervalSeconds: 0.02 });
      reporter.record("client-a", "GET /a");
      await until(() => sent.length === 2);
      assert.equal(sent[0]!.key, sent[1]!.key, String(failure));
      assert.deepEqual(sent[0]!.events, sent[1]!.events, String(failure));
      await reporter.close();
    }
    setLogger(undefined);
  });

  it("drops a batch keelie refuses, and logs the problem's code", async () => {
    const { keelie, sent, answers } = fakeKeelie();
    const lines = captureLog();
    answers.push(400);
    const reporter = new UsageReporter(keelie, { batchSize: 1, flushIntervalSeconds: 0.02 });
    reporter.record("client-a", "GET /a");
    await until(() => sent.length === 1);
    reporter.record("client-a", "GET /b");
    await until(() => sent.length === 2);
    assert.equal(sent[1]!.events[0]!["capability_key"], "GET /b");
    assert.ok(lines.includes("apiable.usage_dropped events=1 status=400 type=usage-out-of-range"));
    await reporter.close();
    setLogger(undefined);
  });

  it("leaves out an event keelie would refuse, without throwing", () => {
    const { keelie } = fakeKeelie();
    const lines = captureLog();
    const reporter = new UsageReporter(keelie);
    reporter.record("", "GET /a");
    reporter.record("client", "x".repeat(256));
    reporter.record("client", "GET /a\n");
    reporter.record("client", "GET /a", { unit: "seconds" as never });
    reporter.record("client", "GET /a", { quantity: 0 });
    reporter.record("client", "GET /a", { credits: -1 });
    reporter.record("client", "GET /a", { outcomeId: "job-1" });
    reporter.record("client", "GET /a", { unit: "outcome", credits: 5 });
    reporter.record("client", "GET /a", { consumerId: "not-a-uuid" });
    assert.deepEqual(lines, [
      "apiable.usage_event_invalid reason=client_id",
      "apiable.usage_event_invalid reason=capability_key",
      "apiable.usage_event_invalid reason=capability_key",
      "apiable.usage_event_invalid reason=unit",
      "apiable.usage_event_invalid reason=quantity",
      "apiable.usage_event_invalid reason=credits",
      "apiable.usage_event_invalid reason=outcome_id",
      "apiable.usage_event_invalid reason=outcome_id",
      "apiable.usage_event_invalid reason=consumer_id",
    ]);
    setLogger(undefined);
    void reporter.close();
  });

  it("never throws on a bad option, and reads null as Python reads None", async () => {
    const { keelie, sent } = fakeKeelie();
    const lines = captureLog();
    const reporter = new UsageReporter(keelie, { batchSize: 100, flushIntervalSeconds: 60 });
    const throwing = {
      get unit(): never {
        throw new Error("a getter that throws");
      },
    };
    const kept: [string, unknown][] = [
      ["options null", null],
      ["credits null", { credits: null }],
      ["outcomeId null", { outcomeId: null }],
      ["consumerId null", { consumerId: null }],
      ["all null", { credits: null, outcomeId: null, consumerId: null }],
      ["outcome, no ID, no credits", { unit: "outcome", outcomeId: null, credits: null }],
    ];
    const dropped: [string, unknown, string][] = [
      ["unit null", { unit: null }, "unit"],
      ["quantity null", { quantity: null }, "quantity"],
      ["options a number", 5, "options"],
      ["options a string", "request", "options"],
      ["options an array", [], "options"],
      ["a getter that throws", throwing, "options"],
      ["outcomeId not a string", { unit: "outcome", outcomeId: 7 }, "outcome_id"],
      ["consumerId not a string", { consumerId: 7 }, "consumer_id"],
      ["credits an object", { credits: {} }, "credits"],
    ];
    for (const [what, options] of kept) {
      assert.doesNotThrow(() => reporter.record("client", "GET /a", options as never), what);
    }
    for (const [what, options] of dropped) {
      assert.doesNotThrow(() => reporter.record("client", "GET /a", options as never), what);
    }
    for (const [what, clientId, capabilityKey] of [
      ["clientId null", null, "GET /a"],
      ["capabilityKey undefined", "client", undefined],
      ["clientId a symbol", Symbol("x"), "GET /a"],
    ] as const) {
      assert.doesNotThrow(() => reporter.record(clientId as never, capabilityKey as never), what);
    }
    assert.deepEqual(lines, [
      ...dropped.map(([, , reason]) => `apiable.usage_event_invalid reason=${reason}`),
      "apiable.usage_event_invalid reason=client_id",
      "apiable.usage_event_invalid reason=capability_key",
      "apiable.usage_event_invalid reason=client_id",
    ]);
    await reporter.close();
    assert.equal(sent.length, 1);
    assert.equal(sent[0]!.events.length, kept.length);
    for (const event of sent[0]!.events) {
      assert.equal(event["quantity"], "1");
      assert.equal(event["credits"], undefined);
      assert.equal(event["consumer_id"], undefined);
    }
    assert.equal(sent[0]!.events.at(-1)!["unit"], "outcome");
    setLogger(undefined);
  });

  it("keys an outcome as the Python SDK does, so it is charged once", async () => {
    const { keelie, sent } = fakeKeelie();
    const reporter = new UsageReporter(keelie, { batchSize: 2, flushIntervalSeconds: 60 });
    reporter.record("client", "POST /videos", { unit: "outcome", credits: 50, outcomeId: "job-42" });
    reporter.record("client", "POST /videos", { unit: "outcome", credits: 50, outcomeId: "job-42" });
    await until(() => sent.length === 1);
    const keys = sent[0]!.events.map((e) => e["idempotency_key"]);
    // uuid.uuid5(KEELIE_OUTCOME_NAMESPACE, "job-42") in Python.
    assert.deepEqual(keys, ["e13e60df-e85b-588a-a945-f15fed07d021", "e13e60df-e85b-588a-a945-f15fed07d021"]);
    await reporter.close();
  });

  it("drops the oldest event when the buffer is full", async () => {
    const { keelie, sent, answers } = fakeKeelie();
    const lines = captureLog();
    answers.push("network");
    const reporter = new UsageReporter(keelie, {
      batchSize: 1,
      maxBufferedEvents: 2,
      flushIntervalSeconds: 0.05,
    });
    reporter.record("client", "first");
    await until(() => sent.length === 1); // fails, and is kept to be sent again
    reporter.record("client", "second");
    reporter.record("client", "third");
    reporter.record("client", "fourth");
    await until(() => sent.length >= 4);
    assert.deepEqual(
      sent.map((s) => s.events[0]!["capability_key"]),
      ["first", "first", "third", "fourth"],
    );
    assert.ok(lines.includes("apiable.usage_dropped events=1 reason=buffer_full"));
    await reporter.close();
    setLogger(undefined);
  });

  it("sends what is left on close, and records nothing after", async () => {
    const { keelie, sent } = fakeKeelie();
    const reporter = new UsageReporter(keelie, { flushIntervalSeconds: 60 });
    reporter.record("client", "GET /a");
    reporter.record("client", "GET /b");
    await reporter.close();
    assert.equal(sent.length, 1);
    assert.equal(sent[0]!.events.length, 2);
    reporter.record("client", "GET /c");
    await reporter.close();
    assert.equal(sent.length, 1);
  });

  it("gives up on close after the timeout, and counts what is lost", async () => {
    const lines = captureLog();
    const never: KeelieFetch = () => new Promise(() => {});
    const reporter = new UsageReporter(never, { flushIntervalSeconds: 60 });
    reporter.record("client", "GET /a");
    await reporter.close(0.05);
    assert.ok(lines.includes("apiable.usage_dropped events=1 reason=closed"));
    setLogger(undefined);
  });

  it("checks its options", () => {
    const { keelie } = fakeKeelie();
    assert.throws(() => new UsageReporter(keelie, { batchSize: 0 }), RangeError);
    assert.throws(() => new UsageReporter(keelie, { batchSize: 1001 }), RangeError);
    assert.throws(() => new UsageReporter(keelie, { flushIntervalSeconds: 0 }), RangeError);
    assert.throws(() => new UsageReporter(keelie, { batchSize: 10, maxBufferedEvents: 5 }), RangeError);
  });
});

describe("amounts", () => {
  it("are written as keelie reads them", () => {
    assert.equal(formatAmount(1, true), "1");
    assert.equal(formatAmount(0.25, true), "0.25");
    assert.equal(formatAmount("1.50", true), "1.50");
    assert.equal(formatAmount("001.5", true), "1.5");
    assert.equal(formatAmount("1.5000000", true), "1.500000");
    // As in Python: zeros past the sixth place are dropped, six places or fewer are sent as given.
    assert.equal(formatAmount("0.0000010", true), "0.000001");
    assert.equal(formatAmount("2.000000000", false), "2.000000");
    assert.equal(formatAmount(10n ** 9n, true), "1000000000");
    assert.equal(formatAmount("0.000001", true), "0.000001");
    assert.equal(formatAmount(0, false), "0");
  });

  it("are refused where keelie would refuse them", () => {
    for (const bad of [0, -1, -0, Number.NaN, Infinity, 1e-7, "0.0000001", "1e3", "-1", "", " 1", "1000000000.000001", 10n ** 9n + 1n, true, null]) {
      assert.equal(formatAmount(bad, true), null, String(bad));
    }
    assert.equal(formatAmount(-0, false), null);
  });
});

describe("UUIDs", () => {
  it("are read and made as Python reads and makes them", () => {
    const canonical = KEELIE_OUTCOME_NAMESPACE;
    for (const form of [
      "{A29FA190-9B27-5A07-A1BA-3A0902A3BDCC}",
      "urn:uuid:a29fa1909b275a07a1ba3a0902a3bdcc",
      "a29f-a1909b275a07a1ba3a0902a3bdcc",
    ]) {
      assert.equal(parseUuid(form), canonical, form);
    }
    assert.equal(parseUuid("a29fa190"), null);
    assert.equal(parseUuid(42), null);
    // uuid.uuid5 in Python, for the same namespace and names.
    assert.equal(uuid5(canonical, "video/7f3a"), "ee03fbee-9a39-53c0-af3a-e31f9479559e");
    assert.equal(uuid5(canonical, "ünïcode-outcome"), "5fefc917-f063-5bb9-ac54-a2c331480f03");
  });
});
