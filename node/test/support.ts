// A fake issuer, a fake keelie and a running Express app, for the tests. No network.

import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";

import type { Fetch } from "../src/keys.js";

export const ISSUER = "https://issuer.example.com/realms/portal-labs";
export const JWKS_URI = `${ISSUER}/protocol/openid-connect/certs`;
export const RESOURCE = "https://api.example.com/v1";
export const ORG_ID = "6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12";
export const OTHER_ORG = "0f2e1d3c-5b4a-4968-8776-a5b4c3d2e1f0";
export const CONSUMER = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9";

export interface KeyPair {
  kid: string;
  privateKey: CryptoKey;
  jwk: JWK;
}

export async function keyPair(kid: string): Promise<KeyPair> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, use: "sig", alg: "RS256" };
  return { kid, privateKey, jwk };
}

/** An issuer that serves its discovery document and key set, and counts the requests. */
export class FakeIssuer {
  keys: JWK[];
  down = false;
  discoveryIssuer = ISSUER;
  requests: string[] = [];

  constructor(public readonly pair: KeyPair) {
    this.keys = [pair.jwk];
  }

  fetch: Fetch = async (input) => {
    this.requests.push(input);
    if (this.down) throw new TypeError("fetch failed");
    if (input === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({ issuer: this.discoveryIssuer, jwks_uri: JWKS_URI });
    }
    if (input === JWKS_URI) return Response.json({ keys: this.keys });
    return new Response(null, { status: 404 });
  };
}

/** The claims of a Consumer's token, by the token rules. */
export function claims(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: RESOURCE,
    azp: "consumer-client",
    org_id: ORG_ID,
    scope: "orders:read profile",
    typ: "Bearer",
    jti: "token-1",
    iat: now,
    exp: now + 300,
    ...extra,
  };
}

/** A token signed with `pair`. A claim given as `undefined` is left out. */
export async function sign(
  pair: KeyPair,
  extra: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
): Promise<string> {
  const payload = Object.fromEntries(
    Object.entries(claims(extra)).filter(([, value]) => value !== undefined),
  );
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: pair.kid, ...header } as { alg: string })
    .sign(pair.privateKey);
}

/** An unsigned token with any header, for the checks that run before a key is fetched. */
export function unsigned(header: Record<string, unknown>, payload = claims()): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${part(header)}.${part(payload)}.${Buffer.from("sig").toString("base64url")}`;
}

/** Start `app` on a free port. */
export async function listen(app: (req: never, res: never) => void): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const { createServer } = await import("node:http");
  const server: Server = createServer(app as never);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

/** A clock the test moves by hand. */
export class Clock {
  now = 1000;
  read = () => this.now;
}

/** Wait until `check` is true, or fail after `ms`. */
export async function until(check: () => boolean, ms = 2000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
