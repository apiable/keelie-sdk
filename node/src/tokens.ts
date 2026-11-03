/**
 * Verify an access token inside your own process.
 *
 * The SDK never asks Apiable whether a token is good. It checks the signature
 * against the issuer's key set (see `keys`) and the claims against what you
 * configured. The checks run in this order, and the first that fails refuses the
 * token:
 *
 * 1. The token parses, its `alg` is `RS256` and it names a `kid`. A token that
 *    says `none` or `HS256` is refused before any key is fetched.
 * 2. The key with that `kid` is in the issuer's key set.
 * 3. The signature, `exp` (required), `nbf`, `iat`, `iss` and `aud`.
 * 4. `azp` names the client, and `org_id` is your own org id.
 * 5. `typ` is `Bearer`. An ID token is signed with the same key.
 *
 * The issuer is your own realm: the `issuer` member of your org in keelie. Each
 * Provider has its own realm, with its own `iss` and its own key set, so a token
 * of another Provider fails at step 2 or 3. The `org_id` check stays as a second
 * line: a Provider whose Consumers keelie made before it had a realm shares one
 * issuer and one key set with others, and there `org_id` tells them apart.
 *
 * Every refusal throws {@link TokenRejected}. Its `reason` is for your log, not
 * for the caller: a caller must not learn "expired" from "wrong key".
 */

import { decodeProtectedHeader, errors, jwtVerify, type JWTPayload } from "jose";

import { ALGORITHM, KeysUnavailable, SigningKeys, UnknownKey, type Status } from "./keys.js";
import { log } from "./log.js";
import { parseUuid } from "./uuid.js";

const TOKEN_TYPE = "Bearer";

/** Clock skew a token is forgiven. */
export const LEEWAY_SECONDS = 30;

export type Reason =
  | "malformed"
  | "algorithm"
  | "kid"
  | "keys_unavailable"
  | "signature"
  | "expired"
  | "not_yet_valid"
  | "issuer"
  | "audience"
  | "claims"
  | "org"
  | "typ";

/** The token does not verify. `reason` is for the log. */
export class TokenRejected extends Error {
  override name = "TokenRejected";
  readonly reason: Reason;

  constructor(reason: Reason, options?: ErrorOptions) {
    super(reason, options);
    this.reason = reason;
  }
}

/** The claims of a verified token that the SDK reads. */
export interface Claims {
  /**
   * The client the token was issued to: the credential. `sub` names the issuer's
   * own service-account user and is ignored.
   */
  readonly azp: string;
  /** Your org id, lowercase with hyphens. */
  readonly orgId: string;
  readonly scopes: ReadonlySet<string>;
  readonly jti: string | null;
  /**
   * When the token expires, from `exp`. While keelie is down, the Consumer is
   * served until then, and refused after.
   */
  readonly expiresAt: Date;
  /**
   * On a token for a person, the Consumer whose credits the person uses: the
   * `consumer_id` claim, lowercase with hyphens. `azp` is then the agent's client,
   * which serves every Consumer. `null` on a credential's token, which names its
   * Consumer by `azp`. Pass it to `UsageReporter.record()` with `azp`.
   */
  readonly consumerId: string | null;
}

export interface TokenVerifierOptions {
  /** The key set. One made from `issuer` unless you give another. */
  keys?: SigningKeys;
  leewaySeconds?: number;
}

/**
 * Verifies the tokens of one issuer, for one audience and one org.
 *
 * `issuer` is the `issuer` member of your org in keelie: your own realm.
 * `audience` is your API's `resource` in keelie, exactly.
 */
export class TokenVerifier {
  readonly #issuer: string;
  readonly #audience: string;
  readonly #orgId: string;
  readonly #keys: SigningKeys;
  readonly #leeway: number;

  constructor(issuer: string, audience: string, orgId: string, options: TokenVerifierOptions = {}) {
    const org = parseUuid(orgId);
    if (org === null) throw new TypeError(`orgId is not a UUID: ${JSON.stringify(orgId)}`);
    this.#issuer = issuer;
    this.#audience = audience;
    this.#orgId = org;
    this.#keys = options.keys ?? new SigningKeys(issuer);
    this.#leeway = options.leewaySeconds ?? LEEWAY_SECONDS;
  }

  /** The `aud` every token must carry: your server's `resource` in keelie. */
  get audience(): string {
    return this.#audience;
  }

  /** The claims of the token, or a rejected promise with {@link TokenRejected}. */
  async verify(token: string): Promise<Claims> {
    try {
      return await this.#verify(token);
    } catch (error) {
      if (error instanceof TokenRejected) {
        log.info(`apiable.token_rejected reason=${error.reason}`);
      }
      throw error;
    }
  }

  /**
   * What the SDK knows of the issuer, from its last fetch of the key set.
   *
   * - `connected`: the last fetch worked.
   * - `degraded`: the last fetch failed. The keys in hand go on verifying. The
   *   next fetch that works makes it `connected` again.
   * - `offline`: no key in hand, so every token is refused. A process is
   *   `offline` until the first token fetches the key set.
   *
   * It makes no network call, and the SDK does not poll. The SDK fetches only on
   * a cold start and for a key it does not know. So while the keys in hand verify
   * every token, an outage of the issuer leaves the status as it is.
   */
  status(): Status {
    return this.#keys.status();
  }

  async #verify(token: string): Promise<Claims> {
    if (typeof token !== "string") throw new TokenRejected("malformed");
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch (error) {
      throw new TokenRejected("malformed", { cause: error });
    }
    if (header.alg !== ALGORITHM) throw new TokenRejected("algorithm");
    const kid = header.kid;
    if (typeof kid !== "string" || kid === "") throw new TokenRejected("kid");

    let key;
    try {
      key = await this.#keys.key(kid);
    } catch (error) {
      if (error instanceof UnknownKey) throw new TokenRejected("kid", { cause: error });
      if (error instanceof KeysUnavailable) {
        throw new TokenRejected("keys_unavailable", { cause: error });
      }
      throw error;
    }

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, key, {
        algorithms: [ALGORITHM],
        issuer: this.#issuer,
        audience: this.#audience,
        clockTolerance: this.#leeway,
        requiredClaims: ["exp"],
      }));
    } catch (error) {
      throw new TokenRejected(reasonOf(error), { cause: error });
    }
    // jose checks `iat` only for a type. A token issued in the future is not
    // yet valid, as in the Python SDK.
    if (typeof payload.iat === "number" && payload.iat > Date.now() / 1000 + this.#leeway) {
      throw new TokenRejected("not_yet_valid");
    }

    const { azp, jti } = payload as Record<string, unknown>;
    const scope = Object.hasOwn(payload, "scope") ? payload["scope"] : "";
    const orgId = parseUuid(payload["org_id"]);
    if (orgId === null) throw new TokenRejected("claims");
    if (
      typeof azp !== "string" ||
      azp === "" ||
      typeof scope !== "string" ||
      !(typeof jti === "string" || jti === undefined || jti === null)
    ) {
      throw new TokenRejected("claims");
    }
    if (orgId !== this.#orgId) throw new TokenRejected("org");
    if (payload["typ"] !== TOKEN_TYPE) throw new TokenRejected("typ");
    const expiresAt = new Date((payload.exp as number) * 1000);
    if (Number.isNaN(expiresAt.getTime())) throw new TokenRejected("claims");
    const consumer = payload["consumer_id"];
    let consumerId: string | null = null;
    if (consumer !== undefined && consumer !== null) {
      consumerId = parseUuid(consumer);
      if (consumerId === null) throw new TokenRejected("claims");
    }
    return Object.freeze({
      azp,
      orgId,
      scopes: new Set(scope.split(/\s+/).filter(Boolean)),
      jti: jti ?? null,
      expiresAt,
      consumerId,
    });
  }
}

function reasonOf(error: unknown): Reason {
  if (error instanceof errors.JWTExpired) return "expired";
  if (error instanceof errors.JWTClaimValidationFailed) {
    switch (error.claim) {
      case "aud":
        return "audience";
      case "iss":
        return "issuer";
      case "exp":
        return error.reason === "missing" ? "claims" : "malformed";
      case "nbf":
      case "iat":
        return error.reason === "check_failed" ? "not_yet_valid" : "malformed";
      default:
        return "claims";
    }
  }
  if (error instanceof errors.JWSSignatureVerificationFailed) return "signature";
  return "malformed";
}
