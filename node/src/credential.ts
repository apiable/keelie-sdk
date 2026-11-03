/**
 * Talk to keelie with your SDK credential.
 *
 * The usage reporter and the AI Catalog call keelie's API. Each call carries a
 * token of the `sdk_credential` from your signup: it may report usage and read
 * your products, and nothing else. {@link sdkCredential} mints that token at your
 * issuer with the client credentials grant, keeps it until shortly before it
 * expires, and mints again on a `401`.
 *
 * The SDK holds no secret of its own. Read the client id and the secret from the
 * environment, never from source code. Never give it your admin credential.
 */

import { FETCH_TIMEOUT_SECONDS, type Fetch } from "./keys.js";

/**
 * Sends one request to keelie. `path` is keelie's path, such as
 * `/usage-events:report`; the base URL and the auth are its own.
 */
export type KeelieFetch = (path: string, init?: RequestInit) => Promise<Response>;

export interface SdkCredentialOptions {
  /** The address of keelie: `KEELIE_URL`. */
  keelieUrl: string;
  /** The token endpoint of keelie's issuer: `KEELIE_TOKEN_URL`. */
  tokenUrl: string;
  /** `sdk_credential.client_id` from the signup answer. */
  clientId: string;
  /** `sdk_credential.client_secret` from the signup answer. */
  clientSecret: string;
  /** Seconds before a call to keelie, or to the token endpoint, gives up. 10 unless you set another. */
  timeoutSeconds?: number;
  fetch?: Fetch;
}

/** A {@link KeelieFetch} that sends a token of your SDK credential with each request. */
export function sdkCredential(options: SdkCredentialOptions): KeelieFetch {
  const base = options.keelieUrl.replace(/\/+$/, "");
  const timeout = (options.timeoutSeconds ?? 10) * 1000;
  const send: Fetch = options.fetch ?? ((input, init) => fetch(input, init));
  const form = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: options.clientId,
    client_secret: options.clientSecret,
  }).toString();
  let token = "";
  let expiresAt = 0;
  let minting: Promise<void> | null = null;

  async function mint(): Promise<void> {
    const response = await send(options.tokenUrl, {
      method: "POST",
      body: form,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      signal: AbortSignal.timeout(timeout),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`the token endpoint answered ${response.status}`);
    }
    const body = (await response.json()) as Record<string, unknown>;
    const accessToken = body["access_token"];
    const lifetime = body["expires_in"];
    if (typeof accessToken !== "string" || typeof lifetime !== "number") {
      throw new Error("the token endpoint answered without a token");
    }
    token = accessToken;
    // Mint again before the token expires.
    expiresAt = performance.now() / 1000 + Math.max(lifetime - 30, lifetime / 2);
  }

  async function fresh(force: boolean): Promise<void> {
    if (minting === null && (force || performance.now() / 1000 >= expiresAt)) {
      minting = mint().finally(() => {
        minting = null;
      });
    }
    if (minting !== null) await minting;
  }

  return async (path, init = {}) => {
    await fresh(false);
    const request = (): Promise<Response> => {
      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${token}`);
      return send(`${base}${path}`, {
        ...init,
        headers,
        signal: init.signal ?? AbortSignal.timeout(timeout),
      });
    };
    const response = await request();
    if (response.status !== 401) return response;
    await response.body?.cancel();
    await fresh(true);
    return request();
  };
}
