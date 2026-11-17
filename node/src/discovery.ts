/**
 * Tell an agent where to get a token for your API.
 *
 * Two standard pieces, served from your own domain:
 *
 * - The protected resource metadata (RFC 9728). It names your API and the one
 *   issuer that mints tokens for it. An agent reads it at the well-known address
 *   of your API. For `https://api.example.com/mcp` that is
 *   `https://api.example.com/.well-known/oauth-protected-resource/mcp`.
 * - A `401` with `WWW-Authenticate: Bearer resource_metadata="..."` on a request
 *   that carries no token (RFC 6750, RFC 9728 section 5). An agent finds the
 *   metadata from this refusal. It does not read the header on a `200`.
 *
 * The issuer serves its own authorization server metadata (RFC 8414). The SDK
 * does not copy it: it names the issuer, and the agent reads the issuer.
 */

import { isOneScope } from "./scopes.js";

export const WELL_KNOWN = "/.well-known/oauth-protected-resource";

/**
 * Where an agent looks for the AI Catalog of a domain, and the media type of
 * each path. ARD v0.91 reads `ard.json` and names no media type for it. The
 * ai-catalog specification reads `ai-catalog.json`, and an MCP proposal points
 * there. Both serve one body. A GET or a HEAD of either needs no token, but only
 * once the AI Catalog middleware serves it. This map is the one list of those
 * paths: the guards and the catalog both read it.
 */
export const ARD_PATH = "/.well-known/ard.json";
export const CATALOG_PATH = "/.well-known/ai-catalog.json";
export const CATALOG_MEDIA_TYPES: ReadonlyMap<string, string> = new Map([
  [ARD_PATH, "application/json"],
  [CATALOG_PATH, "application/ai-catalog+json"],
]);

// Printable ASCII with no space, quote or backslash: the URL goes inside a
// quoted string of the header, as it is.
const URL_CHARS = /^[!#-[\]-~]+$/;

/**
 * The value, if it is an https URL with a host and no user, query, fragment or
 * final slash.
 *
 * The scheme and the host must be lowercase: an uppercase one is refused, not
 * folded. keelie stores your `resource` with the same rule and puts it into
 * `aud` exactly, so the value here and the `aud` of a token compare equal.
 */
function httpsUrl(name: string, value: unknown): { url: string; netloc: string; path: string } {
  if (typeof value !== "string" || !URL_CHARS.test(value)) {
    throw new TypeError(`${name} is not a URL: ${JSON.stringify(value)}`);
  }
  const shape = () =>
    new TypeError(
      `${name} must be https, with a host, no user, query, fragment or final slash: ${JSON.stringify(value)}`,
    );
  if (!/^https:\/\//i.test(value)) throw shape();
  if (value.includes("?") || value.includes("#")) throw shape();
  const rest = value.slice("https://".length);
  const slash = rest.indexOf("/");
  const netloc = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);
  if (netloc.includes("@")) throw shape();
  const port = /^(?:\[[^\]]*\]|[^:]*)(?::(.*))?$/.exec(netloc)?.[1];
  const host = port === undefined ? netloc : netloc.slice(0, netloc.length - port.length - 1);
  if (host === "" || host === "[]") throw shape();
  if (port !== undefined && port !== "" && !(/^\d+$/.test(port) && Number(port) <= 65535)) {
    throw new TypeError(`${name} has a port that is not a number: ${JSON.stringify(value)}`);
  }
  if (path !== "" && path !== "/" && path.endsWith("/")) throw shape();
  if (!value.startsWith("https://") || netloc !== netloc.toLowerCase()) {
    throw new TypeError(`${name} must have a lowercase scheme and host: ${JSON.stringify(value)}`);
  }
  return { url: value, netloc, path };
}

export interface ProtectedResourceMetadataOptions {
  /** Published only if you give it. */
  scopesSupported?: Iterable<string>;
}

/**
 * The RFC 9728 metadata of your API, and the challenge that points to it.
 *
 * `resource` is the URL an agent types for your API, exactly, path included.
 * The metadata repeats it as it is. `authorizationServer` is the issuer, the
 * same value you give `TokenVerifier`. It is one issuer: an agent uses the first
 * and does not try a second.
 */
export class ProtectedResourceMetadata {
  readonly resource: string;
  /** Where the metadata is served on your host, such as `/.well-known/oauth-protected-resource/v1`. */
  readonly path: string;
  /** The full URL of the metadata, from the configuration, never from the request's Host. */
  readonly url: string;
  /** The JSON document, as served. */
  readonly document: string;
  /**
   * Set by the AI Catalog middleware when it is made with this metadata. Until
   * then the catalog paths are guarded like any other.
   */
  aiCatalog = false;
  readonly #prefix: string;

  constructor(
    resource: string,
    authorizationServer: string,
    options: ProtectedResourceMetadataOptions = {},
  ) {
    const parts = httpsUrl("resource", resource);
    const issuer = httpsUrl("authorizationServer", authorizationServer).url;
    this.resource = parts.url;
    // The well-known name goes between the host and the path (RFC 9728 section 3.1).
    this.#prefix = parts.path === "" || parts.path === "/" ? "" : parts.path.replace(/\/+$/, "");
    this.path = WELL_KNOWN + this.#prefix;
    this.url = `https://${parts.netloc}${this.path}`;
    const document: Record<string, unknown> = {
      resource: this.resource,
      authorization_servers: [issuer],
      bearer_methods_supported: ["header"],
    };
    if (options.scopesSupported !== undefined) {
      if (typeof options.scopesSupported === "string") {
        throw new TypeError(
          `give a list of scopes, not one string: ${JSON.stringify(options.scopesSupported)}`,
        );
      }
      const scopes = [...options.scopesSupported];
      if (!scopes.every(isOneScope)) {
        throw new TypeError(`not one scope each: ${JSON.stringify(scopes)}`);
      }
      document["scopes_supported"] = scopes;
    }
    this.document = JSON.stringify(document);
  }

  /** The `WWW-Authenticate` value. Give `"invalid_token"` for a refused token. */
  challenge(error?: string): string {
    if (error === undefined) return `Bearer resource_metadata="${this.url}"`;
    if (!/^[a-z_]+$/.test(error)) {
      throw new TypeError(`not an RFC 6750 error code: ${JSON.stringify(error)}`);
    }
    return `Bearer error="${error}", resource_metadata="${this.url}"`;
  }

  /** True for the path of `resource` and every path below it. */
  protects(path: string): boolean {
    return (
      this.#prefix === "" || path === this.#prefix || path.startsWith(`${this.#prefix}/`)
    );
  }

  /** @internal The path of `resource`, compared without case by the Express guard. */
  get prefix(): string {
    return this.#prefix;
  }
}

/** The Bearer token in an `Authorization` header value, or `null`. The token is not checked. */
export function bearerToken(authorization: string | undefined): string | null {
  if (typeof authorization !== "string") return null;
  const value = authorization.trim();
  const at = value.indexOf(" ");
  const scheme = at === -1 ? value : value.slice(0, at);
  const token = at === -1 ? "" : value.slice(at + 1).trim();
  return scheme.toLowerCase() === "bearer" && token !== "" ? token : null;
}
