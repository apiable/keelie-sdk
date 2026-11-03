import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { KeysUnavailable, SigningKeys, UnknownKey } from "../src/keys.js";
import { Clock, FakeIssuer, ISSUER, JWKS_URI, keyPair } from "./support.js";

const pair = await keyPair("key-1");
const DISCOVERY = `${ISSUER}/.well-known/openid-configuration`;

function setup() {
  const issuer = new FakeIssuer(pair);
  const clock = new Clock();
  const keys = new SigningKeys(`${ISSUER}/`, { fetch: issuer.fetch, clock: clock.read });
  return { issuer, clock, keys };
}

describe("SigningKeys", () => {
  it("fetches the key set once for every caller that finds it cold", async () => {
    const { issuer, keys } = setup();
    await Promise.all(Array.from({ length: 20 }, () => keys.key("key-1")));
    assert.deepEqual(issuer.requests, [DISCOVERY, JWKS_URI]);
    assert.equal(keys.status(), "connected");
  });

  it("keeps the jwks_uri, and fetches an unknown kid once a minute at most", async () => {
    const { issuer, clock, keys } = setup();
    await keys.key("key-1");
    await assert.rejects(keys.key("made-up-1"), UnknownKey); // 59 s since the fetch? no: a new interval has not started
    issuer.requests = [];
    clock.now += 30;
    await assert.rejects(keys.key("made-up-2"), UnknownKey);
    await assert.rejects(keys.key("made-up-3"), UnknownKey);
    assert.deepEqual(issuer.requests, []);
    clock.now += 31;
    await assert.rejects(keys.key("made-up-4"), UnknownKey);
    assert.deepEqual(issuer.requests, [JWKS_URI]);
  });

  it("picks up a rotated key on its first token", async () => {
    const { issuer, clock, keys } = setup();
    await keys.key("key-1");
    const next = await keyPair("key-2");
    issuer.keys = [pair.jwk, next.jwk];
    clock.now += 60;
    await keys.key("key-2");
    await keys.key("key-1");
  });

  it("refuses a discovery document of another issuer", async () => {
    const { issuer, keys } = setup();
    issuer.discoveryIssuer = "https://issuer.example.com/realms/other";
    await assert.rejects(keys.key("key-1"), KeysUnavailable);
    assert.deepEqual(issuer.requests, [DISCOVERY]);
    assert.equal(keys.status(), "offline");
  });

  it("caches nothing on a cold failure, so the next caller tries again", async () => {
    const { issuer, keys } = setup();
    issuer.down = true;
    await assert.rejects(keys.key("key-1"), KeysUnavailable);
    issuer.down = false;
    await keys.key("key-1");
    assert.equal(keys.status(), "connected");
  });

  it("goes on verifying with the keys in hand when a refresh fails", async () => {
    const { issuer, clock, keys } = setup();
    await keys.key("key-1");
    issuer.down = true;
    clock.now += 60;
    await assert.rejects(keys.key("key-2"), UnknownKey);
    assert.equal(keys.status(), "degraded");
    await keys.key("key-1");
    // A failed fetch also waits an interval before the next.
    issuer.requests = [];
    await assert.rejects(keys.key("key-3"), UnknownKey);
    assert.deepEqual(issuer.requests, []);
    issuer.down = false;
    clock.now += 60;
    await assert.rejects(keys.key("key-4"), UnknownKey);
    assert.equal(keys.status(), "connected");
  });

  it("loads only RSA signing keys for RS256, and only their public part", async () => {
    const { issuer, keys } = setup();
    const other = await keyPair("key-2");
    issuer.keys = [
      { ...other.jwk, kid: "enc", use: "enc" },
      { ...other.jwk, kid: "ps", alg: "PS256" },
      { kty: "EC", kid: "ec", crv: "P-256", x: "x", y: "y" },
      { kty: "RSA", kid: "broken", n: "!", e: "AQAB" },
      { ...other.jwk, kid: "no-use", use: undefined, alg: undefined },
      { ...pair.jwk, d: "a private member, published by mistake" },
      "not a key",
    ] as never;
    await keys.key("key-1");
    await keys.key("no-use");
    for (const kid of ["enc", "ps", "ec", "broken"]) {
      await assert.rejects(keys.key(kid), UnknownKey);
    }
  });

  it("is offline until the first token", () => {
    const { keys } = setup();
    assert.equal(keys.status(), "offline");
  });
});
