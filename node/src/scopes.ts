/**
 * Check the scope of a verified token against the route it calls.
 *
 * You give the SDK one map: for each route, the scope a token must carry. A
 * route is the HTTP method and the path template your framework matched, such
 * as `"GET /orders/:orderId"`. Give the template, not the path of the request,
 * so that one entry covers every order.
 *
 * The check is strict:
 *
 * - A scope matches only itself. `orders:read` does not grant `orders`, and
 *   `orders` does not grant `orders:read`.
 * - A route matches only itself. There is no prefix and no wildcard.
 * - A route that is not in the map is refused. Add every route that a token may
 *   call.
 *
 * Every refusal throws {@link InsufficientScope}. Answer it with `403`, not
 * `401`: the token is good, it does not allow this call.
 */

import { log } from "./log.js";
import type { Claims } from "./tokens.js";

/** The token does not carry the scope the route requires. */
export class InsufficientScope extends Error {
  override name = "InsufficientScope";
  readonly method: string;
  readonly route: string;

  constructor(method: string, route: string) {
    super(`${method} ${route}`);
    this.method = method;
    this.route = route;
  }
}

/** One scope, by the rule that splits the token's scope claim. */
export function isOneScope(scope: unknown): scope is string {
  return typeof scope === "string" && scope !== "" && !/\s/.test(scope);
}

/** The scope that each route requires. */
export class ScopeMap {
  readonly #routes = new Map<string, string>();

  /**
   * `routes` maps each `"METHOD /template"` to its one scope, such as
   * `{ "GET /orders/:orderId": "orders:read" }`. The method and the template are
   * split at the first space.
   */
  constructor(routes: Readonly<Record<string, string>>) {
    for (const [entry, scope] of Object.entries(routes)) {
      const at = entry.indexOf(" ");
      if (at <= 0 || at === entry.length - 1) {
        throw new TypeError(`not "METHOD /route": ${JSON.stringify(entry)}`);
      }
      const method = entry.slice(0, at);
      const route = entry.slice(at + 1);
      if (!isOneScope(scope)) {
        throw new TypeError(`not one scope: ${JSON.stringify(scope)} for ${method} ${route}`);
      }
      const key = ScopeMap.#key(method, route);
      if (this.#routes.has(key)) throw new TypeError(`route given twice: ${method} ${route}`);
      this.#routes.set(key, scope);
    }
  }

  /** @internal A map from pairs that are already split, such as `["tools/call", toolName]`. */
  static fromPairs(pairs: Iterable<readonly [string, string, string]>): ScopeMap {
    const map = new ScopeMap({});
    for (const [method, route, scope] of pairs) {
      if (!isOneScope(scope)) {
        throw new TypeError(`not one scope: ${JSON.stringify(scope)} for ${method} ${route}`);
      }
      const key = ScopeMap.#key(method, route);
      if (map.#routes.has(key)) throw new TypeError(`route given twice: ${method} ${route}`);
      map.#routes.set(key, scope);
    }
    return map;
  }

  /** Return if the token may call the route, else throw {@link InsufficientScope}. */
  check(claims: Claims, method: string, route: string): void {
    const upper = method.toUpperCase();
    const required = this.#routes.get(ScopeMap.#key(upper, route));
    if (required === undefined || !claims.scopes.has(required)) {
      log.info(
        `apiable.scope_refused reason=${required === undefined ? "unmapped" : "scope"} ` +
          `client=${claims.azp} method=${upper} ` +
          // A route that is not in the map can come from the request, such as an
          // MCP tool name, and stays out of the log.
          `route=${required !== undefined ? route : "-"}`,
      );
      throw new InsufficientScope(upper, route);
    }
  }

  static #key(method: string, route: string): string {
    return `${method.toUpperCase()}\u0000${route}`;
  }
}
