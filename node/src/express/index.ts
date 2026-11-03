/**
 * The Express adapters, for Express 4 and 5.
 *
 * Every adapter checks a token through one core, here, and through nothing else.
 * Every adapter refuses a token in the same way: `401`, an empty body, and
 * `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`. The
 * answer is the same for every reason. The reason goes to your log only.
 *
 * - {@link tokenGuard}, for a REST API. It checks the token and puts the claims
 *   on `req.keelieClaims`.
 * - {@link scopeGuard}, on each route of a REST API. It checks the scope of the
 *   route.
 * - {@link mcpGuard}, for a Streamable HTTP MCP server. It checks the token, the
 *   scope of each tool call, and reports each tool call.
 * - {@link aiCatalog}, which serves your AI Catalog with no token.
 *
 * Each guard also serves the RFC 9728 metadata at `metadata.path`, with no
 * token, and refuses a request with no token with `401` and
 * `WWW-Authenticate: Bearer resource_metadata="..."`, so an agent can find your
 * issuer. Paths outside `resource` and a CORS preflight (`OPTIONS`) pass
 * untouched.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";

import type { AiCatalog } from "../catalog.js";
import { CATALOG_MEDIA_TYPES, bearerToken, type ProtectedResourceMetadata } from "../discovery.js";
import { DuplicateKey, TooDeep, parseStrictJson } from "../json.js";
import { log } from "../log.js";
import { InsufficientScope, ScopeMap } from "../scopes.js";
import { TokenRejected, type Claims, type TokenVerifier } from "../tokens.js";
import type { UsageReporter } from "../usage.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** The claims of the request's token, set by {@link tokenGuard} or {@link mcpGuard}. */
      keelieClaims?: Claims;
    }
  }
}

export interface GuardOptions {
  verifier: TokenVerifier;
  metadata: ProtectedResourceMetadata;
}

/**
 * The REST adapter: checks the token, and gives the claims to your routes.
 *
 * ```ts
 * app.use(tokenGuard({ verifier, metadata }));
 * ```
 *
 * A route reads the claims as `req.keelieClaims`.
 *
 * It does not check the scope. Middleware mounted with `app.use` runs before the
 * router picks a route, so it cannot see the route's template. Put
 * {@link scopeGuard} on each route, or call `ScopeMap.check()` in it. A route
 * without either is authenticated, but it has no scope check.
 */
export function tokenGuard(options: GuardOptions): RequestHandler {
  return guard(options, (claims, req, _res, next) => {
    req.keelieClaims = claims;
    next();
  });
}

/**
 * Checks the scope of the route it is on, against `scopes`.
 *
 * ```ts
 * const scopes = new ScopeMap({ "GET /v1/orders/:orderId": "orders:read" });
 * app.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), (req, res) => { ... });
 * ```
 *
 * The route is the method and the template Express matched: the path the router
 * was mounted at, then the route's own path, as you wrote them. A refused token
 * gets `403` with `WWW-Authenticate: Bearer error="insufficient_scope"` and an
 * empty body.
 *
 * A router mounted at a path with a parameter, such as `/orgs/:orgId`, gives the
 * request's own value for that part, not the template. There, call
 * `scopes.check(req.keelieClaims, method, template)` in the route instead.
 *
 * {@link tokenGuard} must run first. Without its claims, the request fails with
 * an error, so that the mistake is seen.
 */
export function scopeGuard(scopes: ScopeMap, metadata: ProtectedResourceMetadata): RequestHandler {
  const refusal = metadata.challenge("insufficient_scope");
  return (req, res, next) => {
    const claims = req.keelieClaims;
    if (claims === undefined) {
      next(new Error("keelie: scopeGuard needs tokenGuard to run before it"));
      return;
    }
    const template = typeof req.route?.path === "string" ? req.route.path : null;
    try {
      // A route with no plain template, such as a regular expression, is in no map.
      scopes.check(claims, req.method, template === null ? "\u0000" : `${req.baseUrl}${template}`);
    } catch (error) {
      if (!(error instanceof InsufficientScope)) throw error;
      respond(res, 403, { "WWW-Authenticate": refusal });
      return;
    }
    next();
  };
}

// The method of a tool call. It is also the method half of each key in the
// adapter's ScopeMap: ["tools/call", <tool name>].
const TOOLS_CALL = "tools/call";

export const MAX_BODY_BYTES = 4 * 1024 * 1024;

// The methods that carry no tool call. They pass after the token check.
const PASS_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "DELETE"]);

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const INVALID_PARAMS = -32602;
// An application code: MCP keeps -32000 to -32099 for itself.
const INSUFFICIENT_SCOPE = -31001;

export interface McpGuardOptions extends GuardOptions {
  /** Each tool name and the one scope it requires, such as `{ get_order: "orders:read" }`. */
  tools: Readonly<Record<string, string>>;
  /** The process's one usage reporter. */
  reporter: UsageReporter;
  maxBodyBytes?: number;
}

/**
 * Checks the token and the tool's scope, and reports each tool call.
 *
 * Give the MCP endpoint itself as the `resource` of `metadata`: every `POST`
 * under it is read as JSON-RPC. Mount it before any body parser, and hand
 * `req.body` to your transport:
 *
 * ```ts
 * app.use(mcpGuard({ verifier, metadata, tools, reporter }));
 * app.post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));
 * ```
 *
 * What it checks on a request whose token verified:
 *
 * - A `POST` body is read in full, up to `maxBodyBytes`, and parsed once. The
 *   parsed body goes on as `req.body`. The method and the tool name come from
 *   the body only, never from the `Mcp-Method` or `Mcp-Name` header.
 * - A `tools/call` needs the scope you mapped to its tool. A tool that is not in
 *   the map is refused. Add every tool that a token may call.
 * - Every other method passes with no scope check: `initialize`,
 *   `notifications/*`, `ping`, `tools/list`, and also `resources/*` and
 *   `prompts/*`. Apiable sells tools, not resources or prompts.
 * - `GET`, `HEAD` and `DELETE` pass, and so does a CORS preflight (`OPTIONS`).
 *   Every other method gets `405`, with `Allow: GET, POST, DELETE`.
 *
 * Every refusal is a JSON-RPC error:
 *
 * - `400`, `-32700`: the body is not UTF-8 JSON, or it is nested too deeply.
 * - `400`, `-32600`: the body is an array, is not an object, has a key twice,
 *   or is a `tools/call` with no `id`. A batch is refused on purpose: MCP
 *   removed batches in 2025-06-18, so a 2025-03-26 client that batches is cut.
 * - `400`, `-32602`: a `tools/call` whose `params.name` is not a string.
 * - `413`, `-32600`: the body is larger than `maxBodyBytes`.
 * - `403`, `-31001`, with `WWW-Authenticate: Bearer error="insufficient_scope"`:
 *   the token does not carry the tool's scope. The answer does not name the
 *   scope, on purpose: an unmapped tool and an unscoped tool look the same, so
 *   the answer does not show the map.
 *
 * The usage event is recorded when your server starts a `2xx` response, not at
 * the end of its body, so a `text/event-stream` reply streams through
 * unbuffered. The event carries no `credits`.
 *
 * If a body parser has already read the body, the guard reads `req.body` as it
 * found it. It then cannot tell a key given twice, so mount it first.
 */
export function mcpGuard(options: McpGuardOptions): RequestHandler {
  const { reporter, metadata } = options;
  const maxBodyBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
  const scopes = ScopeMap.fromPairs(
    Object.entries(options.tools).map(([name, scope]) => [TOOLS_CALL, name, scope] as const),
  );
  const scopeRefusal = metadata.challenge("insufficient_scope");

  return guard(options, async (claims, req, res, next) => {
    req.keelieClaims = claims;
    if (PASS_METHODS.has(req.method)) {
      next();
      return;
    }
    if (req.method !== "POST") {
      // A body under any other method could carry a tool call: refuse it.
      respond(res, 405, { Allow: "GET, POST, DELETE" });
      return;
    }

    const read = await readBody(req, maxBodyBytes);
    if (read.kind === "gone") return; // the client went away
    if (read.kind === "too_large") {
      res.setHeader("Connection", "close");
      jsonRpcError(res, 413, null, INVALID_REQUEST, "Request body too large");
      return;
    }

    let request: unknown;
    if (read.kind === "parsed") {
      request = read.value;
    } else {
      try {
        request = parseStrictJson(read.text);
      } catch (error) {
        if (error instanceof DuplicateKey) {
          jsonRpcError(res, 400, null, INVALID_REQUEST, "Invalid Request");
        } else if (error instanceof SyntaxError || error instanceof TooDeep || error instanceof RangeError) {
          jsonRpcError(res, 400, null, PARSE_ERROR, "Parse error");
        } else {
          throw error;
        }
        return;
      }
    }
    if (request === null || typeof request !== "object" || Array.isArray(request)) {
      jsonRpcError(res, 400, null, INVALID_REQUEST, "Invalid Request");
      return;
    }

    let tool: string | null = null;
    const message = request as Record<string, unknown>;
    if (message["method"] === TOOLS_CALL) {
      const id = message["id"];
      if (!(typeof id === "string" || (typeof id === "number" && Number.isInteger(id)))) {
        jsonRpcError(res, 400, null, INVALID_REQUEST, "Invalid Request");
        return;
      }
      const params = message["params"];
      const name =
        params !== null && typeof params === "object" && !Array.isArray(params)
          ? (params as Record<string, unknown>)["name"]
          : undefined;
      if (typeof name !== "string") {
        jsonRpcError(res, 400, id, INVALID_PARAMS, "Invalid params");
        return;
      }
      try {
        scopes.check(claims, TOOLS_CALL, name);
      } catch (error) {
        if (!(error instanceof InsufficientScope)) throw error;
        jsonRpcError(res, 403, id, INSUFFICIENT_SCOPE, "Insufficient scope", {
          "WWW-Authenticate": scopeRefusal,
        });
        return;
      }
      tool = name;
    }

    req.body = request;
    if (tool !== null) countToolCall(res, reporter, claims, tool);
    next();
  });
}

/**
 * Serves your AI Catalog at `/.well-known/ard.json` and
 * `/.well-known/ai-catalog.json`, with no token. Other requests pass untouched.
 *
 * ```ts
 * app.use(aiCatalog(new AiCatalog(keelie, metadata)));
 * ```
 *
 * The order beside the token guards does not matter: once the catalog is made
 * with `metadata`, the guards let a GET or a HEAD of its two paths pass.
 */
export function aiCatalog(catalog: AiCatalog): RequestHandler {
  return (req, res, next) => {
    const path = rawPath(req);
    if ((req.method !== "GET" && req.method !== "HEAD") || !CATALOG_MEDIA_TYPES.has(path)) {
      next();
      return;
    }
    catalog.answer(path).then(
      (answer) => {
        if (answer === null) {
          next();
          return;
        }
        respond(res, answer.status, answer.headers, answer.body);
      },
      (error: unknown) => next(error),
    );
  };
}

type Handle = (claims: Claims, req: Request, res: Response, next: NextFunction) => void | Promise<void>;

/**
 * The part every adapter shares. An adapter adds only what it does with the claims.
 *
 * The verifier's audience must be the `resource` of the metadata, or the guard
 * does not start. An agent asks keelie for a token with that `resource` (RFC
 * 8707), and keelie writes your org's `resource` into `aud`. A verifier for
 * another audience would refuse every such token, or accept a token for another
 * server. Set your org's `resource` in keelie to the same value.
 */
function guard({ verifier, metadata }: GuardOptions, handle: Handle): RequestHandler {
  if (verifier.audience !== metadata.resource) {
    throw new TypeError(
      `the verifier's audience ${JSON.stringify(verifier.audience)} is not the resource ` +
        `${JSON.stringify(metadata.resource)}: give both the same value`,
    );
  }
  const challenge = metadata.challenge();
  const refusal = metadata.challenge("invalid_token");
  return (req, res, next) => {
    const path = rawPath(req);
    if (path === metadata.path && (req.method === "GET" || req.method === "HEAD")) {
      // Before the token check: with a resource at the root, the metadata is
      // under it, and the agent reads it with no token.
      respond(res, 200, { "Content-Type": "application/json" }, metadata.document);
      return;
    }
    if (!guarded(req, path, metadata)) {
      next();
      return;
    }
    const token = bearerToken(req.headers.authorization);
    if (token === null) {
      respond(res, 401, { "WWW-Authenticate": challenge });
      return;
    }
    verifier.verify(token).then(
      async (claims) => handle(claims, req, res, next),
      (error: unknown) => {
        if (!(error instanceof TokenRejected)) throw error;
        respond(res, 401, { "WWW-Authenticate": refusal });
      },
    ).catch((error: unknown) => next(error));
  };
}

/**
 * True for a request under `resource` that must carry a token.
 *
 * A CORS preflight (`OPTIONS`) and every path outside `resource` pass. So does a
 * GET or a HEAD of the metadata, and of the AI Catalog at either of its paths
 * when the catalog serves it. Any other method on those paths needs a token.
 *
 * The path is compared in every form Express could route it by: as sent, with
 * its dot segments resolved, with its escapes read and its doubled slashes
 * folded, and without case, because Express routes without case unless you set
 * `case sensitive routing`. A request that is under `resource` in any of these
 * forms is guarded. It can only guard more than the router serves, never less.
 */
function guarded(req: Request, path: string, metadata: ProtectedResourceMetadata): boolean {
  if (req.method === "OPTIONS") return false;
  if (
    (req.method === "GET" || req.method === "HEAD") &&
    (path === metadata.path || (metadata.aiCatalog && CATALOG_MEDIA_TYPES.has(path)))
  ) {
    return false;
  }
  const prefix = metadata.prefix.toLowerCase();
  if (prefix === "") return true;
  return pathForms(path).some((form) => {
    const lower = form.toLowerCase();
    return lower === prefix || lower.startsWith(`${prefix}/`);
  });
}

function pathForms(path: string): string[] {
  const forms = new Set<string>([path]);
  try {
    forms.add(new URL(path, "http://h").pathname);
  } catch {
    // Not a path the URL parser reads; the other forms still count.
  }
  for (const form of [...forms]) {
    try {
      forms.add(decodeURIComponent(form));
    } catch {
      // A broken escape; the other forms still count.
    }
  }
  for (const form of [...forms]) forms.add(form.replace(/\/{2,}/g, "/"));
  return [...forms];
}

/** The path of the request as the client sent it, without the query, whatever router it is in. */
function rawPath(req: Request): string {
  const url = req.originalUrl ?? req.url;
  const end = url.search(/[?#]/);
  return end === -1 ? url : url.slice(0, end);
}

function respond(
  res: Response,
  status: number,
  headers: Record<string, string>,
  body: string | Uint8Array = "",
): void {
  const bytes = typeof body === "string" ? Buffer.from(body) : body;
  res.status(status);
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
  res.setHeader("Content-Length", String(bytes.byteLength));
  // Node sends no body for a HEAD request, whatever is given here.
  res.end(bytes);
}

function jsonRpcError(
  res: Response,
  status: number,
  id: unknown,
  code: number,
  message: string,
  headers: Record<string, string> = {},
): void {
  log.info(`apiable.mcp_refused status=${status} code=${code}`);
  const body = JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
  respond(res, status, { ...headers, "Content-Type": "application/json" }, body);
}

type Read =
  | { kind: "text"; text: string }
  | { kind: "parsed"; value: unknown }
  | { kind: "too_large" }
  | { kind: "gone" };

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The request's body, read in full up to `max` bytes. */
async function readBody(req: Request, max: number): Promise<Read> {
  if (req.readableEnded) {
    // A body parser read it first. Read what it left.
    const body: unknown = req.body;
    if (Buffer.isBuffer(body)) return decoded(body, max);
    if (typeof body === "string") return decoded(Buffer.from(body), max);
    return { kind: "parsed", value: body };
  }
  return new Promise<Read>((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (read: Read) => {
      if (settled) return;
      settled = true;
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onGone);
      req.off("close", onClose);
      resolve(read);
    };
    const onData = (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > max) {
        req.pause();
        finish({ kind: "too_large" });
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(decoded(Buffer.concat(chunks), max));
    const onGone = () => finish({ kind: "gone" });
    const onClose = () => {
      if (!req.readableEnded) finish({ kind: "gone" });
    };
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onGone);
    req.on("close", onClose);
  }).then((read) => {
    // A body parser further down finds the body read, and leaves `req.body` alone.
    (req as unknown as { _body?: boolean })._body = true;
    return read;
  });
}

function decoded(bytes: Uint8Array, max: number): Read {
  if (bytes.byteLength > max) return { kind: "too_large" };
  try {
    return { kind: "text", text: UTF8.decode(bytes) };
  } catch {
    // Not UTF-8: the JSON parser refuses it as it refuses any other bad body.
    return { kind: "text", text: "\u0000" };
  }
}

/** Record one event when the tool call's response starts with 2xx. */
function countToolCall(res: Response, reporter: UsageReporter, claims: Claims, tool: string): void {
  const writeHead = res.writeHead;
  let seen = false;
  // Node calls writeHead for every response, also when only `end()` is called.
  res.writeHead = function (this: Response, ...args: Parameters<Response["writeHead"]>) {
    if (!seen) {
      seen = true;
      const status = typeof args[0] === "number" ? args[0] : this.statusCode;
      if (status >= 200 && status < 300) {
        reporter.record(claims.azp, tool, { unit: "tool_call", consumerId: claims.consumerId });
      }
    }
    return writeHead.apply(this, args);
  } as Response["writeHead"];
}
