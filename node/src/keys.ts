/**
 * The issuer's signing keys, kept in the process.
 *
 * The first token fetches the key set: the issuer's discovery document names its
 * `jwks_uri`, and that document holds the keys. A `kid` the cache does not know
 * fetches once more, then is refused. That is how a rotated key is picked up
 * without a restart: the first token it signs fetches it.
 *
 * Once a key set is in hand, at most one fetch a minute, however many unknown
 * `kid` values arrive and whether or not the fetch succeeds. A flood of made-up
 * `kid` values costs the issuer one request a minute, also while the issuer is
 * down.
 *
 * With no key set in hand (a cold start), every caller waits on one fetch and
 * gets its outcome, a failure too. A failed cold fetch is kept for 5 seconds:
 * a token in that window is refused at once, and the issuer is not asked. The
 * next token after the window fetches again. Each document has a total deadline
 * of 5 seconds, so a cold fetch takes 10 seconds at most.
 *
 * A key set with no usable signing key counts as a failed fetch. The keys in
 * hand stay, and go on verifying. A set with a usable key replaces the old set,
 * so a rotation still retires the old key.
 *
 * The issuer and the `jwks_uri` must be https. Plain http is taken only for a
 * loopback host.
 *
 * The `jwks_uri` from the first discovery is kept for the life of the process.
 * A discovery document whose `issuer` is not the configured one is refused, and
 * no key is fetched from it (OpenID Connect Discovery 1.0, section 4.3). Each
 * Provider has its own realm, so each issuer has its own key set: a document of
 * another realm must never fill this one's.
 */

import { importJWK, type CryptoKey, type JWK, type KeyObject } from "jose";

import { requireHttps } from "./discovery.js";
import { errorName, log } from "./log.js";

/** The one algorithm the SDK accepts, in the key set and on the token. */
export const ALGORITHM = "RS256";

/**
 * How long the cache refuses a second fetch after one completed. Shorter than
 * any token lifetime, so a rotation is never waited out.
 */
export const REFRESH_INTERVAL_SECONDS = 60;

/** The total deadline of each fetch: the discovery document, and the key set. */
export const FETCH_TIMEOUT_SECONDS = 5;

/**
 * How long a failed cold fetch is kept. In that window a token is refused at
 * once, with no request to the issuer.
 */
export const COLD_FAILURE_SECONDS = 5;

export type Status = "connected" | "degraded" | "offline";

export type Key = CryptoKey | KeyObject;

/** The `fetch` the SDK uses. The global one unless you give another, such as in a test. */
export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/** No key in the set has this `kid`, after one refresh. */
export class UnknownKey extends Error {
  override name = "UnknownKey";
}

/** The key set could not be fetched, and no key set is in hand. */
export class KeysUnavailable extends Error {
  override name = "KeysUnavailable";
}

export interface SigningKeysOptions {
  fetch?: Fetch;
  /** Seconds, from any fixed point. `performance.now()` unless you give another. */
  clock?: () => number;
  refreshIntervalSeconds?: number;
  /** The total deadline of each fetch, in seconds. 5 unless you give another. */
  timeoutSeconds?: number;
}

/** The issuer's RS256 signing keys, fetched on first use and refreshed on an unknown `kid`. */
export class SigningKeys {
  readonly #issuer: string;
  readonly #fetch: Fetch;
  readonly #clock: () => number;
  readonly #interval: number;
  readonly #timeout: number;
  #keys = new Map<string, Key>();
  #jwksUri: string | null = null;
  #fetchedAt: number | null = null;
  #refreshFailed = false;
  #inFlight: Promise<void> | null = null;
  // The last cold failure: when, and the name of its error.
  #coldFailedAt: number | null = null;
  #coldFailure = "";

  constructor(issuer: string, options: SigningKeysOptions = {}) {
    this.#issuer = requireHttps("issuer", issuer).replace(/\/+$/, "");
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
    this.#clock = options.clock ?? (() => performance.now() / 1000);
    this.#interval = options.refreshIntervalSeconds ?? REFRESH_INTERVAL_SECONDS;
    this.#timeout = options.timeoutSeconds ?? FETCH_TIMEOUT_SECONDS;
  }

  /** The key with this id, fetching the set once if it is not there. */
  async key(kid: string): Promise<Key> {
    const known = this.#keys.get(kid);
    if (known !== undefined) return known;
    // Every caller that finds the cache cold, or its kid missing, waits on the
    // same fetch. The issuer answers one request, not one for each caller. A
    // caller that waited on a fetch that failed cold gets that failure.
    while (this.#inFlight !== null) await this.#inFlight;
    if (!this.#keys.has(kid) && this.#keys.size === 0 && this.#coldFailedAt !== null) {
      if (this.#clock() - this.#coldFailedAt < COLD_FAILURE_SECONDS) {
        // Inside the window: refused at once, and the issuer is not asked.
        log.warn(`apiable.keys_unavailable: ${this.#coldFailure}`);
        throw new KeysUnavailable(this.#coldFailure);
      }
    }
    if (!this.#keys.has(kid) && this.#mayFetch()) {
      this.#inFlight = this.#refresh().finally(() => {
        this.#inFlight = null;
      });
      await this.#inFlight;
    }
    const key = this.#keys.get(kid);
    if (key !== undefined) return key;
    throw new UnknownKey(kid);
  }

  /** `offline` with no key, `degraded` if the last fetch failed, else `connected`. */
  status(): Status {
    if (this.#keys.size === 0) return "offline";
    return this.#refreshFailed ? "degraded" : "connected";
  }

  #mayFetch(): boolean {
    return this.#fetchedAt === null || this.#clock() - this.#fetchedAt >= this.#interval;
  }

  async #refresh(): Promise<void> {
    let keys: Map<string, Key>;
    try {
      keys = await signingKeys(await this.#fetchKeySet());
      // A set with no usable key is a failed fetch: it must not empty the cache.
      if (keys.size === 0) throw new KeySetError("no usable key");
    } catch (error) {
      if (this.#keys.size === 0) {
        // Cold: nothing to verify with. The failure is kept for a short window,
        // then the next caller tries again.
        this.#coldFailedAt = this.#clock();
        this.#coldFailure = errorName(error);
        log.warn(`apiable.keys_unavailable: ${errorName(error)}`);
        throw new KeysUnavailable(errorName(error), { cause: error });
      }
      // Warm: the keys in hand go on verifying, and the issuer is not asked
      // again for another interval.
      this.#fetchedAt = this.#clock();
      this.#refreshFailed = true;
      log.warn(`apiable.keys_not_refreshed: ${errorName(error)}`);
      return;
    }
    this.#keys = keys;
    this.#fetchedAt = this.#clock();
    this.#refreshFailed = false;
    this.#coldFailedAt = null;
    log.info(`apiable.keys_loaded kids=${JSON.stringify([...keys.keys()].sort())}`);
  }

  async #fetchKeySet(): Promise<unknown> {
    let jwksUri = this.#jwksUri;
    if (jwksUri === null) {
      const document = await this.#getJson(`${this.#issuer}/.well-known/openid-configuration`);
      const issuer = field(document, "issuer");
      if (typeof issuer !== "string" || issuer.replace(/\/+$/, "") !== this.#issuer) {
        throw new KeySetError("issuer");
      }
      const uri = field(document, "jwks_uri");
      if (typeof uri !== "string") throw new KeySetError("jwks_uri");
      try {
        jwksUri = requireHttps("jwks_uri", uri);
      } catch {
        // The keys must come over https, as the discovery document did.
        throw new KeySetError("jwks_uri");
      }
    }
    const keySet = field(await this.#getJson(jwksUri), "keys");
    this.#jwksUri = jwksUri;
    return keySet;
  }

  /**
   * One document. The deadline covers the whole fetch, the body too, and holds
   * even for a `fetch` that does not read the signal.
   */
  #getJson(url: string): Promise<unknown> {
    return withDeadline(this.#timeout * 1000, async (signal) => {
      const response = await this.#fetch(url, {
        signal,
        // As in Python: a redirect is not followed, so the keys come from the
        // addresses the issuer names, or from nowhere. It fails the fetch.
        redirect: "error",
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        throw new KeySetError(`status ${response.status}`);
      }
      return (await response.json()) as unknown;
    });
  }
}

/** The outcome of `run`, or a `TimeoutError` after `ms`. The signal aborts at the deadline. */
function withDeadline<T>(ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const error = new DOMException("The fetch of the key set timed out", "TimeoutError");
      controller.abort(error);
      reject(error);
    }, ms);
    run(controller.signal).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

class KeySetError extends Error {
  override name = "KeySetError";
}

const MIN_MODULUS_BITS = 2048;

function modulusLength(key: Key): number {
  // jose gives a WebCrypto key on Node; a KeyObject is read for completeness.
  const details = (key as { asymmetricKeyDetails?: { modulusLength?: number } }).asymmetricKeyDetails;
  const algorithm = (key as { algorithm?: { modulusLength?: number } }).algorithm;
  return details?.modulusLength ?? algorithm?.modulusLength ?? 0;
}

function field(document: unknown, name: string): unknown {
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    throw new KeySetError("document");
  }
  if (!Object.hasOwn(document, name)) throw new KeySetError(name);
  return (document as Record<string, unknown>)[name];
}

async function signingKeys(keySet: unknown): Promise<Map<string, Key>> {
  if (!Array.isArray(keySet)) throw new KeySetError("keys");
  const keys = new Map<string, Key>();
  for (const jwk of keySet as unknown[]) {
    // The issuer can publish an encryption key beside the signing key. Only an
    // RSA key for signing, with the one algorithm and a kid, verifies a token.
    if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) continue;
    const { kid, kty, use, alg, n, e } = jwk as Record<string, unknown>;
    if (
      typeof kid !== "string" ||
      kty !== "RSA" ||
      (use !== undefined && use !== null && use !== "sig") ||
      (alg !== undefined && alg !== null && alg !== ALGORITHM)
    ) {
      continue;
    }
    try {
      if (typeof n !== "string" || typeof e !== "string") throw new KeySetError("n, e");
      // The public members only: a private member published by mistake is never loaded.
      const publicKey: JWK = { kty: "RSA", n, e, alg: ALGORITHM };
      const key = await importJWK(publicKey, ALGORITHM);
      if (key instanceof Uint8Array) continue; // a symmetric key, never an RSA one
      // jose loads a broken modulus as a key of 0 bits, and verifies nothing
      // with an RSA key under 2048 bits. Skip it here, where the log says why.
      if (modulusLength(key) < MIN_MODULUS_BITS) throw new KeySetError("modulus");
      keys.set(kid, key);
    } catch {
      // A key the SDK cannot load is skipped. The rest of the set loads.
      log.warn(`apiable.key_skipped kid=${JSON.stringify(kid)}`);
    }
  }
  return keys;
}
