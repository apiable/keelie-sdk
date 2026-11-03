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
 * down. With no key set in hand, a failed fetch caches nothing, and the next
 * caller tries again.
 *
 * The `jwks_uri` from the first discovery is kept for the life of the process.
 * A discovery document whose `issuer` is not the configured one is refused, and
 * no key is fetched from it (OpenID Connect Discovery 1.0, section 4.3). Each
 * Provider has its own realm, so each issuer has its own key set: a document of
 * another realm must never fill this one's.
 */

import { importJWK, type CryptoKey, type JWK, type KeyObject } from "jose";

import { errorName, log } from "./log.js";

/** The one algorithm the SDK accepts, in the key set and on the token. */
export const ALGORITHM = "RS256";

/**
 * How long the cache refuses a second fetch after one completed. Shorter than
 * any token lifetime, so a rotation is never waited out.
 */
export const REFRESH_INTERVAL_SECONDS = 60;

export const FETCH_TIMEOUT_SECONDS = 5;

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
}

/** The issuer's RS256 signing keys, fetched on first use and refreshed on an unknown `kid`. */
export class SigningKeys {
  readonly #issuer: string;
  readonly #fetch: Fetch;
  readonly #clock: () => number;
  readonly #interval: number;
  #keys = new Map<string, Key>();
  #jwksUri: string | null = null;
  #fetchedAt: number | null = null;
  #refreshFailed = false;
  #inFlight: Promise<void> | null = null;

  constructor(issuer: string, options: SigningKeysOptions = {}) {
    this.#issuer = issuer.replace(/\/+$/, "");
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
    this.#clock = options.clock ?? (() => performance.now() / 1000);
    this.#interval = options.refreshIntervalSeconds ?? REFRESH_INTERVAL_SECONDS;
  }

  /** The key with this id, fetching the set once if it is not there. */
  async key(kid: string): Promise<Key> {
    const known = this.#keys.get(kid);
    if (known !== undefined) return known;
    // Every caller that finds the cache cold, or its kid missing, waits on the
    // same fetch. The issuer answers one request, not one for each caller.
    while (this.#inFlight !== null) await this.#inFlight;
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
    } catch (error) {
      if (this.#fetchedAt === null) {
        // Cold: nothing to verify with. Nothing is cached, so the next caller
        // tries again.
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
      jwksUri = uri;
    }
    const keySet = field(await this.#getJson(jwksUri), "keys");
    this.#jwksUri = jwksUri;
    return keySet;
  }

  async #getJson(url: string): Promise<unknown> {
    const response = await this.#fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_SECONDS * 1000),
      redirect: "follow",
    });
    if (!response.ok) throw new KeySetError(`status ${response.status}`);
    return response.json();
  }
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
