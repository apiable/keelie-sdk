/**
 * Report usage to keelie in batches, off the request path.
 *
 * {@link UsageReporter.record} puts one event in a buffer in memory and returns.
 * It does no I/O and never awaits, so it adds no time to the request that calls
 * it. A timer sends the buffer to keelie's usage endpoint: when it holds a full
 * batch, and at each interval. The interval is 5 seconds unless you set another.
 *
 * What the SDK reports is telemetry. It feeds the Provider's dashboards and the
 * Consumer's spend cap. Apiable never puts it on an invoice.
 *
 * Each event carries its own idempotency key, and each batch carries an
 * `Idempotency-Key`. A batch that fails on the way is sent again later with the
 * same key and the same body, so keelie keeps each event once.
 *
 * A token for a person names its Consumer in `consumer_id`: its `azp` is an
 * agent's client, which serves every Consumer. Pass `claims.consumerId` to
 * `record()` with each event. keelie then burns that Consumer's credits. On a
 * credential's token it is `null`, and nothing is sent.
 *
 * An outcome is charged once. `record(..., { unit: "outcome", outcomeId })`
 * makes the event's key from the outcome ID, with
 * {@link KEELIE_OUTCOME_NAMESPACE}. The same outcome then has the same key on
 * every repeat, in every process and in every language, and keelie keeps the
 * key in every month. A repeat burns nothing.
 *
 * A report that fails never stops a request:
 *
 * - A network error, a `401`, `408`, `409`, `429` or a `5xx` keeps the batch.
 *   The reporter sends it again after one interval. It does not read
 *   `Retry-After`.
 * - Any other answer drops the batch, with a log line. A retry gets the same
 *   answer. `usage-out-of-range` is one of these: the batch would take a counter
 *   or a balance past the largest value keelie keeps.
 * - When the buffer is full, the oldest event goes, and a log line counts it.
 *
 * keelie refuses an event older than the start of the previous month. After an
 * outage that long, a batch that holds such an event is dropped.
 *
 * Nothing is written to disk. {@link UsageReporter.close} sends what is left at
 * shutdown. Events it cannot send in time are lost, with a log line.
 */

import { randomUUID } from "node:crypto";

import type { KeelieFetch } from "./credential.js";
import { errorName, log } from "./log.js";
import { parseUuid, uuid5 } from "./uuid.js";

/** The one place that names keelie's usage endpoint. */
export const USAGE_PATH = "/usage-events:report";

export type Unit = "request" | "tool_call" | "token" | "outcome";
const UNITS: ReadonlySet<string> = new Set(["request", "tool_call", "token", "outcome"]);

/**
 * The namespace of an outcome's key: `uuid5(KEELIE_OUTCOME_NAMESPACE, outcomeId)`.
 * Fixed for good, and the same in every language. A UUIDv5 and not a random key:
 * the key must be the same on every repeat of the outcome, so that keelie
 * charges it once.
 */
export const KEELIE_OUTCOME_NAMESPACE = "a29fa190-9b27-5a07-a1ba-3a0902a3bdcc";

// What keelie takes in one event, and in one batch.
export const MAX_NAME_LENGTH = 255;
const MAX_AMOUNT_DIGITS = 10; // 10 ** 9, the largest amount, has ten digits
const PLACES = 6;
export const MAX_BATCH_SIZE = 1000;
export const BATCH_SIZE = 50;
/**
 * At most 5 seconds. A Consumer's balance may go below zero for 60 seconds at
 * most, and that window must hold one flush, one failed flush, a retry and a
 * burst.
 */
export const FLUSH_INTERVAL_SECONDS = 5;
export const MAX_BUFFERED_EVENTS = 10_000;
export const CLOSE_TIMEOUT_SECONDS = 10;

// The answers that can change on a retry. Every other failure drops the batch.
// A `401` is one: the credential mints a new token for the next try.
const RETRY_STATUSES: ReadonlySet<number> = new Set([401, 408, 409, 429]);

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;
const PROBLEM_CODE = /^[a-z0-9-]{1,64}$/;

/**
 * An amount: a whole number, a decimal with at most six places, or a string
 * that holds one, such as `"0.25"`. A string keeps exact cents that a `number`
 * cannot.
 */
export type Amount = number | bigint | string;

export interface RecordOptions {
  unit?: Unit;
  quantity?: Amount;
  /** What the call costs the Consumer's balance. Leave it out when the call is free. */
  credits?: Amount;
  /**
   * The outcome of a `unit: "outcome"` event, such as the ID of the job. It must
   * be unique across all your Consumers. The event's key is made from it, so
   * keelie charges the outcome once, however often it is reported. An outcome
   * with credits needs it. Any other unit must not have it.
   */
  outcomeId?: string;
  /**
   * `claims.consumerId`: the Consumer of a token for a person, whose credits the
   * call burns. Always pass it. It is `null` on a credential's token: keelie
   * refuses a `consumer_id` there. keelie refuses a batch with an event of an
   * agent's client that has no `consumer_id`.
   */
  consumerId?: string | null;
}

export interface UsageReporterOptions {
  batchSize?: number;
  flushIntervalSeconds?: number;
  maxBufferedEvents?: number;
}

type EventBody = Record<string, string>;
type Batch = { key: string; body: string; count: number };

/**
 * Collects usage events and sends them to keelie in batches, in the background.
 *
 * `keelie` sends a request to keelie with the auth of a credential that may
 * report usage: use {@link sdkCredential}.
 *
 * Make one reporter for the process. The first `record()` starts its timer.
 * Call {@link close} when the process shuts down. The timer does not keep the
 * process alive.
 */
export class UsageReporter {
  readonly #keelie: KeelieFetch;
  readonly #batchSize: number;
  readonly #interval: number;
  readonly #max: number;
  #events: EventBody[] = [];
  // The batch on its way, kept as sent: a retry repeats its key and its body.
  #pending: Batch | null = null;
  #dropped = 0;
  #closed = false;
  #timer: NodeJS.Timeout | null = null;
  #flushing: Promise<boolean> | null = null;
  // While a batch waits to be sent again, a full buffer does not hurry it.
  #retrying = false;

  constructor(keelie: KeelieFetch, options: UsageReporterOptions = {}) {
    const batchSize = options.batchSize ?? BATCH_SIZE;
    const interval = options.flushIntervalSeconds ?? FLUSH_INTERVAL_SECONDS;
    const max = options.maxBufferedEvents ?? MAX_BUFFERED_EVENTS;
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
      throw new RangeError(`batchSize must be from 1 to ${MAX_BATCH_SIZE}`);
    }
    if (!(interval > 0)) throw new RangeError("flushIntervalSeconds must be more than 0");
    if (!Number.isInteger(max) || max < batchSize) {
      throw new RangeError("maxBufferedEvents must be at least batchSize");
    }
    this.#keelie = keelie;
    this.#batchSize = batchSize;
    this.#interval = interval;
    this.#max = max;
  }

  /**
   * Put one event in the buffer, and return at once.
   *
   * `clientId` is the `azp` of the Consumer's token. `capabilityKey` names the
   * route or the tool that was called.
   *
   * It never throws and never waits. An event keelie would refuse is logged and
   * left out, so it cannot cost the other events of its batch.
   */
  record(clientId: string, capabilityKey: string, options: RecordOptions = {}): void {
    if (this.#closed) return;
    const { unit = "request", quantity = 1, credits, outcomeId, consumerId } = options;
    const amount = formatAmount(quantity, true);
    const cost = credits === undefined ? null : formatAmount(credits, false);
    const consumer = consumerId === undefined || consumerId === null ? null : parseUuid(consumerId);
    let reason: string | null = null;
    if (!nameOk(clientId)) reason = "client_id";
    else if (!nameOk(capabilityKey)) reason = "capability_key";
    else if (typeof unit !== "string" || !UNITS.has(unit)) reason = "unit";
    else if (amount === null) reason = "quantity";
    else if (credits !== undefined && cost === null) reason = "credits";
    else if (outcomeId !== undefined && (unit !== "outcome" || !nameOk(outcomeId))) {
      reason = "outcome_id";
    } else if (outcomeId === undefined && unit === "outcome" && cost !== null && /[1-9]/.test(cost)) {
      // Without the ID, each repeat of the outcome would burn the balance again.
      reason = "outcome_id";
    } else if (consumerId !== undefined && consumerId !== null && consumer === null) {
      reason = "consumer_id";
    }
    if (reason !== null) {
      // A fixed word: the value can come from the request, and stays out of the log.
      log.warn(`apiable.usage_event_invalid reason=${reason}`);
      return;
    }
    const event: EventBody = {
      idempotency_key:
        outcomeId === undefined ? randomUUID() : uuid5(KEELIE_OUTCOME_NAMESPACE, outcomeId),
      client_id: clientId,
      capability_key: capabilityKey,
      unit,
      quantity: amount!,
      ts: new Date().toISOString(),
    };
    if (cost !== null) event["credits"] = cost;
    if (consumer !== null) event["consumer_id"] = consumer;
    if (this.#events.length >= this.#max) {
      // The oldest event goes to take this one.
      this.#events.shift();
      this.#dropped += 1;
    }
    this.#events.push(event);
    if (this.#timer === null) this.#schedule(this.#interval);
    if (this.#events.length >= this.#batchSize && !this.#retrying) this.#wake();
  }

  /** Start the timer. `record()` starts it too; this is for a process that wants it running first. */
  start(): void {
    if (!this.#closed && this.#timer === null) this.#schedule(this.#interval);
  }

  /**
   * Stop the timer, and send what is in the buffer, once.
   *
   * If a batch fails, or `timeoutSeconds` pass, what is not sent is dropped,
   * with one log line. It never rejects.
   */
  async close(timeoutSeconds: number = CLOSE_TIMEOUT_SECONDS): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
    let timeout: NodeJS.Timeout | undefined;
    const expired = new Promise<void>((resolve) => {
      timeout = setTimeout(resolve, timeoutSeconds * 1000);
    });
    try {
      // A flush already on its way finishes first; then one more sends the rest.
      if (this.#flushing !== null) await Promise.race([this.#flushing, expired]);
      await Promise.race([this.#flush().catch(() => false), expired]);
    } finally {
      clearTimeout(timeout);
    }
    const lost = this.#events.length + (this.#pending?.count ?? 0);
    if (lost) log.warn(`apiable.usage_dropped events=${lost} reason=closed`);
  }

  #schedule(seconds: number): void {
    if (this.#closed) return;
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = setTimeout(() => this.#tick(), seconds * 1000);
    this.#timer.unref();
  }

  #wake(): void {
    if (this.#flushing === null) this.#schedule(0);
  }

  #tick(): void {
    this.#timer = null;
    if (this.#flushing !== null) return;
    const flushing = this.#flush().catch((error: unknown) => {
      // The reporter must outlive any failure.
      log.warn(`apiable.usage_flush_failed error=${errorName(error)}`);
      return false;
    });
    this.#flushing = flushing;
    void flushing.then((done) => {
      this.#flushing = null;
      // keelie or the network failed: wait one interval, whatever fills the
      // buffer, then send the same batch again.
      this.#retrying = !done;
      if (!done || this.#events.length > 0 || this.#pending !== null) {
        this.#schedule(done && this.#events.length >= this.#batchSize ? 0 : this.#interval);
      }
    });
  }

  /** Send every batch in the buffer. False if a batch must be sent again later. */
  async #flush(): Promise<boolean> {
    try {
      while (this.#pending !== null || this.#events.length > 0) {
        if (this.#pending === null) this.#pending = this.#nextBatch();
        if (!(await this.#send(this.#pending))) return false;
        this.#pending = null;
      }
      return true;
    } finally {
      this.#logDropped();
    }
  }

  #nextBatch(): Batch {
    const events = this.#events.splice(0, this.#batchSize);
    return { key: randomUUID(), body: JSON.stringify({ events }), count: events.length };
  }

  /** Send one batch. True when it is done with: kept by keelie, or dropped. */
  async #send({ key, body, count }: Batch): Promise<boolean> {
    let response: Response;
    try {
      response = await this.#keelie(USAGE_PATH, {
        method: "POST",
        body,
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
      });
    } catch (error) {
      log.warn(`apiable.usage_not_sent events=${count} error=${errorName(error)}`);
      return false;
    }
    const status = response.status;
    if (response.ok) {
      await response.body?.cancel();
      log.debug(`apiable.usage_sent events=${count}`);
      return true;
    }
    if (RETRY_STATUSES.has(status) || status >= 500) {
      await response.body?.cancel();
      log.warn(`apiable.usage_not_sent events=${count} status=${status}`);
      return false;
    }
    log.warn(
      `apiable.usage_dropped events=${count} status=${status} type=${await problemType(response)}`,
    );
    return true;
  }

  #logDropped(): void {
    if (this.#dropped) {
      log.warn(`apiable.usage_dropped events=${this.#dropped} reason=buffer_full`);
      this.#dropped = 0;
    }
  }
}

function nameOk(name: unknown): name is string {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    name.length <= MAX_NAME_LENGTH &&
    !CONTROL.test(name)
  );
}

/**
 * The amount as keelie reads it, a plain decimal string with no sign and at most
 * six places, or `null` if keelie would refuse it.
 */
export function formatAmount(value: unknown, positive: boolean): string | null {
  let text: string;
  if (typeof value === "bigint") {
    text = value.toString();
  } else if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) return null;
    // The shortest decimal that reads back as this number. An exponent means
    // more places, or more digits, than keelie keeps.
    text = String(value);
  } else if (typeof value === "string") {
    text = value;
  } else {
    return null;
  }
  const match = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (match === null) return null;
  const whole = match[1]!.replace(/^0+(?=\d)/, "");
  let fraction = match[2] ?? "";
  // Zeros past the sixth place change nothing, and keelie reads six at most.
  if (fraction.length > PLACES) {
    if (/[1-9]/.test(fraction.slice(PLACES))) return null;
    fraction = fraction.slice(0, PLACES);
  }
  if (whole.length > MAX_AMOUNT_DIGITS) return null;
  if (whole.length === MAX_AMOUNT_DIGITS && (whole !== "1000000000" || /[1-9]/.test(fraction))) {
    return null;
  }
  if (positive && !/[1-9]/.test(whole + fraction)) return null;
  return fraction === "" ? whole : `${whole}.${fraction}`;
}

/** The last segment of the problem's `type`, such as `usage-out-of-range`. */
async function problemType(response: Response): Promise<string> {
  let problem: unknown;
  try {
    problem = await response.json();
  } catch {
    return "unknown";
  }
  const kind =
    problem !== null && typeof problem === "object" && !Array.isArray(problem)
      ? (problem as Record<string, unknown>)["type"]
      : undefined;
  if (typeof kind !== "string") return "unknown";
  const code = kind.replace(/\/+$/, "").split("/").pop() ?? "";
  // keelie's codes are short and plain. Anything else stays out of the log.
  return PROBLEM_CODE.test(code) ? code : "unknown";
}
