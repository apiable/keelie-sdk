/**
 * Serve your AI Catalog from your own domain.
 *
 * The catalog is at `/.well-known/ard.json`, where ARD v0.91 looks for it, and at
 * `/.well-known/ai-catalog.json`, where the ai-catalog specification looks and an
 * MCP proposal points. Both paths serve the same body, from the same copy.
 *
 * keelie builds the catalog from your published plans. {@link AiCatalog} fetches
 * it from keelie with your credential, keeps it for 60 seconds, and serves it
 * with no token. A plan you publish shows here within 60 seconds, and within up
 * to 120 seconds at a client that caches the answer.
 *
 * The SDK does not change the document. It keeps no copy past 60 seconds: if
 * keelie does not answer when the copy is old, the answer is `503`, not an old
 * catalog. After a failure, it asks keelie again after 10 seconds, not on each
 * request.
 */

import type { KeelieFetch } from "./credential.js";
import { CATALOG_MEDIA_TYPES, type ProtectedResourceMetadata } from "./discovery.js";
import { errorName, log } from "./log.js";

/** The one place that names keelie's catalog endpoint. */
export const KEELIE_CATALOG_PATH = "/ai-catalog";

export const CACHE_SECONDS = 60;
export const RETRY_SECONDS = 10;

/** What to answer a GET or a HEAD of a catalog path. */
export interface CatalogAnswer {
  status: 200 | 503;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface AiCatalogOptions {
  /** Seconds, from any fixed point. `performance.now()` unless you give another. */
  clock?: () => number;
}

/**
 * The catalog, fetched from keelie and kept for 60 seconds.
 *
 * `keelie` carries the auth of a credential that may read products, as for the
 * usage reporter. `metadata` is the one your token guard uses. Making it with
 * `metadata` tells the token guards to let a GET or a HEAD of the two catalog
 * paths pass with no token. Without it, they guard the paths like any other.
 *
 * Serve it with the Express middleware `aiCatalog()` from `keelie/express`, or
 * call {@link answer} from any other server.
 */
export class AiCatalog {
  readonly #keelie: KeelieFetch;
  readonly #clock: () => number;
  #body: Uint8Array | null = null;
  #fetchedAt = 0;
  #failedAt: number | null = null;
  #inFlight: Promise<Uint8Array | null> | null = null;

  constructor(keelie: KeelieFetch, metadata: ProtectedResourceMetadata, options: AiCatalogOptions = {}) {
    this.#keelie = keelie;
    metadata.aiCatalog = true;
    this.#clock = options.clock ?? (() => performance.now() / 1000);
  }

  /** The answer for `path`, or `null` if `path` is not a catalog path. */
  async answer(path: string): Promise<CatalogAnswer | null> {
    const mediaType = CATALOG_MEDIA_TYPES.get(path);
    if (mediaType === undefined) return null;
    const body = await this.#catalog();
    if (body === null) {
      return {
        status: 503,
        headers: { "Retry-After": "10", "Cache-Control": "no-store" },
        body: new Uint8Array(),
      };
    }
    return { status: 200, headers: { "Content-Type": mediaType, "Cache-Control": "max-age=60" }, body };
  }

  /** The catalog, fetched again when the copy is 60 seconds old. `null` if keelie fails. */
  async #catalog(): Promise<Uint8Array | null> {
    if (this.#settled()) return this.#body;
    // One fetch for many requests at once: the others read what it got, or its failure.
    this.#inFlight ??= this.#fetch().finally(() => {
      this.#inFlight = null;
    });
    return this.#inFlight;
  }

  async #fetch(): Promise<Uint8Array | null> {
    this.#body = null;
    let response: Response;
    try {
      response = await this.#keelie(KEELIE_CATALOG_PATH);
    } catch (error) {
      log.warn(`apiable.catalog_fetch_failed error=${errorName(error)}`);
      this.#failedAt = this.#clock();
      return null;
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      log.warn(`apiable.catalog_fetch_failed status=${response.status}`);
      this.#failedAt = this.#clock();
      return null;
    }
    let body: Uint8Array;
    try {
      body = new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      log.warn(`apiable.catalog_fetch_failed error=${errorName(error)}`);
      this.#failedAt = this.#clock();
      return null;
    }
    this.#body = body;
    this.#fetchedAt = this.#clock();
    this.#failedAt = null;
    return body;
  }

  /** True while the copy is fresh, or while a failure is recent: no fetch is due. */
  #settled(): boolean {
    const now = this.#clock();
    if (this.#failedAt !== null) return now - this.#failedAt < RETRY_SECONDS;
    return this.#body !== null && now - this.#fetchedAt < CACHE_SECONDS;
  }
}
