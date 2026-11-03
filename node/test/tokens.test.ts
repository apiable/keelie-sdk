import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { SignJWT } from "jose";

import { SigningKeys } from "../src/keys.js";
import { TokenRejected, TokenVerifier, type Reason } from "../src/tokens.js";
import {
  CONSUMER,
  FakeIssuer,
  ISSUER,
  ORG_ID,
  OTHER_ORG,
  RESOURCE,
  keyPair,
  sign,
  unsigned,
} from "./support.js";

const pair = await keyPair("key-1");

function setup() {
  const issuer = new FakeIssuer(pair);
  const verifier = new TokenVerifier(ISSUER, RESOURCE, ORG_ID, {
    keys: new SigningKeys(ISSUER, { fetch: issuer.fetch }),
  });
  return { issuer, verifier };
}

async function rejects(verifier: TokenVerifier, token: string, reason: Reason): Promise<void> {
  await assert.rejects(verifier.verify(token), (error: unknown) => {
    assert.ok(error instanceof TokenRejected);
    assert.equal(error.reason, reason);
    return true;
  });
}

describe("TokenVerifier", () => {
  it("returns the claims of a good token", async () => {
    const { verifier } = setup();
    const claims = await verifier.verify(await sign(pair));
    assert.equal(claims.azp, "consumer-client");
    assert.equal(claims.orgId, ORG_ID);
    assert.deepEqual([...claims.scopes].sort(), ["orders:read", "profile"]);
    assert.equal(claims.jti, "token-1");
    assert.equal(claims.consumerId, null);
    assert.ok(claims.expiresAt.getTime() > Date.now());
    assert.ok(Object.isFrozen(claims));
  });

  it("reads consumer_id in its canonical form", async () => {
    const { verifier } = setup();
    const claims = await verifier.verify(await sign(pair, { consumer_id: CONSUMER.toUpperCase() }));
    assert.equal(claims.consumerId, CONSUMER);
  });

  it("refuses a token for another algorithm before any key is fetched", async () => {
    const { issuer, verifier } = setup();
    await rejects(verifier, unsigned({ alg: "none", kid: "key-1" }), "algorithm");
    await rejects(verifier, unsigned({ alg: "HS256", kid: "key-1" }), "algorithm");
    await rejects(verifier, unsigned({ alg: "RS256" }), "kid");
    await rejects(verifier, unsigned({ alg: "RS256", kid: "" }), "kid");
    assert.deepEqual(issuer.requests, []);
  });

  it("refuses what does not parse", async () => {
    const { verifier } = setup();
    await rejects(verifier, "not-a-token", "malformed");
    await rejects(verifier, "", "malformed");
  });

  it("refuses an unknown kid", async () => {
    const { verifier } = setup();
    const other = await keyPair("key-2");
    await rejects(verifier, await sign(other), "kid");
  });

  it("refuses a signature of another key with the same kid", async () => {
    const { verifier } = setup();
    const impostor = await keyPair("key-1");
    await rejects(verifier, await sign(impostor), "signature");
  });

  it("checks the times", async () => {
    const { verifier } = setup();
    const now = Math.floor(Date.now() / 1000);
    await rejects(verifier, await sign(pair, { exp: now - 31 }), "expired");
    await verifier.verify(await sign(pair, { exp: now - 5 })); // inside the leeway
    await rejects(verifier, await sign(pair, { nbf: now + 60 }), "not_yet_valid");
    await rejects(verifier, await sign(pair, { iat: now + 60 }), "not_yet_valid");
    await rejects(verifier, await sign(pair, { exp: undefined }), "claims");
    await rejects(verifier, await sign(pair, { exp: "soon" }), "malformed");
  });

  it("checks the issuer and the audience", async () => {
    const { verifier } = setup();
    await rejects(verifier, await sign(pair, { iss: "https://issuer.example.com/realms/other" }), "issuer");
    await rejects(verifier, await sign(pair, { aud: "https://api.example.com/v2" }), "audience");
    await rejects(verifier, await sign(pair, { aud: undefined }), "audience");
    await verifier.verify(await sign(pair, { aud: ["https://other.example.com", RESOURCE] }));
  });

  it("checks the claims keelie writes", async () => {
    const { verifier } = setup();
    await rejects(verifier, await sign(pair, { org_id: OTHER_ORG }), "org");
    await rejects(verifier, await sign(pair, { org_id: "nope" }), "claims");
    await rejects(verifier, await sign(pair, { org_id: undefined }), "claims");
    await rejects(verifier, await sign(pair, { azp: undefined }), "claims");
    await rejects(verifier, await sign(pair, { azp: "" }), "claims");
    await rejects(verifier, await sign(pair, { scope: ["orders:read"] }), "claims");
    await rejects(verifier, await sign(pair, { jti: 7 }), "claims");
    await rejects(verifier, await sign(pair, { typ: "ID" }), "typ");
    await rejects(verifier, await sign(pair, { typ: undefined }), "typ");
    await rejects(verifier, await sign(pair, { consumer_id: "nope" }), "claims");
    await rejects(verifier, await sign(pair, { consumer_id: 12 }), "claims");
  });

  it("reads a missing scope as no scope", async () => {
    const { verifier } = setup();
    const claims = await verifier.verify(await sign(pair, { scope: undefined }));
    assert.equal(claims.scopes.size, 0);
  });

  it("refuses a token signed with HS256 even with a known kid", async () => {
    const { verifier } = setup();
    const token = await new SignJWT({ iss: ISSUER })
      .setProtectedHeader({ alg: "HS256", kid: "key-1" })
      .sign(new TextEncoder().encode("a shared secret that is long enough"));
    await rejects(verifier, token, "algorithm");
  });

  it("refuses every token while the issuer cannot be reached, and says why", async () => {
    const { issuer, verifier } = setup();
    issuer.down = true;
    await rejects(verifier, await sign(pair), "keys_unavailable");
    assert.equal(verifier.status(), "offline");
  });

  it("does not start with an org id that is not a UUID", () => {
    assert.throws(() => new TokenVerifier(ISSUER, RESOURCE, "portal-labs"), TypeError);
  });
});
