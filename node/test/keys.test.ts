import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { KeysUnavailable, SigningKeys, UnknownKey, type Fetch } from "../src/keys.js";
import { setLogger } from "../src/log.js";
import { Clock, FakeIssuer, ISSUER, JWKS_URI, keyPair, listen } from "./support.js";

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

  it("keeps a cold failure for 5 seconds, then tries again", async () => {
    const { issuer, clock, keys } = setup();
    const lines: string[] = [];
    setLogger({ debug() {}, info() {}, warn: (m) => lines.push(m) });
    try {
      issuer.down = true;
      await assert.rejects(keys.key("key-1"), KeysUnavailable);
      assert.equal(issuer.requests.length, 1);
      issuer.down = false;
      // Inside the window: refused at once, with the same log line, and the issuer is not asked.
      clock.now += 4.9;
      await assert.rejects(keys.key("key-1"), KeysUnavailable);
      assert.equal(issuer.requests.length, 1);
      assert.deepEqual(lines, ["apiable.keys_unavailable: TypeError", "apiable.keys_unavailable: TypeError"]);
      // After the window: the next caller fetches again.
      clock.now += 0.2;
      await keys.key("key-1");
      assert.equal(keys.status(), "connected");
    } finally {
      setLogger(undefined);
    }
  });

  it("makes one fetch for every cold caller of a failing issuer, and each gets its failure", async () => {
    const { issuer, keys } = setup();
    issuer.down = true;
    const results = await Promise.allSettled(Array.from({ length: 20 }, () => keys.key("key-1")));
    assert.ok(results.every((r) => r.status === "rejected" && r.reason instanceof KeysUnavailable));
    assert.deepEqual(issuer.requests, [DISCOVERY]);
  });

  it("ends a fetch that hangs at its deadline, with one fetch for every cold caller", async () => {
    const requests: string[] = [];
    // A fetch that never answers and does not read the signal.
    const hang: Fetch = (input) => {
      requests.push(input);
      return new Promise<Response>(() => {});
    };
    const keys = new SigningKeys(ISSUER, { fetch: hang, timeoutSeconds: 0.2 });
    const started = performance.now();
    const results = await Promise.allSettled(Array.from({ length: 20 }, () => keys.key("key-1")));
    const elapsed = performance.now() - started;
    assert.ok(results.every((r) => r.status === "rejected" && r.reason instanceof KeysUnavailable));
    assert.deepEqual(requests, [DISCOVERY]);
    assert.ok(elapsed >= 150 && elapsed < 1000, `${elapsed} ms`);
  });

  it("ends a fetch whose body never ends at its deadline", async () => {
    const stalled: Fetch = async () =>
      new Response(new ReadableStream({ start() {} }), { headers: { "Content-Type": "application/json" } });
    const keys = new SigningKeys(ISSUER, { fetch: stalled, timeoutSeconds: 0.1 });
    await assert.rejects(keys.key("key-1"), KeysUnavailable);
  });

  it("counts a key set with no usable key as a failed fetch", async () => {
    const { issuer, clock, keys } = setup();
    await keys.key("key-1");
    issuer.keys = [];
    clock.now += 60;
    await assert.rejects(keys.key("key-2"), UnknownKey);
    // The keys in hand stay, and go on verifying.
    await keys.key("key-1");
    assert.equal(keys.status(), "degraded");
    // A set with a usable key still replaces the old set: a rotation retires the old key.
    const next = await keyPair("key-2");
    issuer.keys = [next.jwk];
    clock.now += 60;
    await keys.key("key-2");
    clock.now += 60;
    await assert.rejects(keys.key("key-1"), UnknownKey);
    assert.equal(keys.status(), "connected");
  });

  it("is unavailable on a cold start whose key set has no usable key", async () => {
    const { issuer, keys } = setup();
    issuer.keys = [];
    await assert.rejects(keys.key("key-1"), KeysUnavailable);
    assert.equal(keys.status(), "offline");
  });

  it("needs an https issuer, and plain http on a loopback host only", () => {
    for (const bad of ["http://issuer.example.com/realms/a", "ftp://issuer.example.com", "issuer.example.com", "https://user@issuer.example.com"]) {
      assert.throws(() => new SigningKeys(bad), TypeError, bad);
    }
    for (const good of ["https://issuer.example.com/realms/a", "http://localhost:8080/realms/a", "http://127.0.0.1/realms/a", "http://[::1]:8080/realms/a", "http://LOCALHOST:8080/realms/a"]) {
      assert.doesNotThrow(() => new SigningKeys(good), good);
    }
  });

  it("fetches no key set from a jwks_uri that is not https", async () => {
    const requests: string[] = [];
    const fetch: Fetch = async (input) => {
      requests.push(input);
      return Response.json({ issuer: ISSUER, jwks_uri: "http://issuer.example.com/certs" });
    };
    const keys = new SigningKeys(ISSUER, { fetch });
    await assert.rejects(keys.key("key-1"), KeysUnavailable);
    assert.deepEqual(requests, [DISCOVERY]);
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

  it("follows no redirect, from the discovery document or the key set", async () => {
    // Another origin serves a discovery document and a key set of its own.
    const reached: string[] = [];
    let issuerUrl = "";
    const other = await listen(((req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => {
      reached.push(req.url ?? "");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify(
          req.url === "/certs" ? { keys: [pair.jwk] } : { issuer: issuerUrl, jwks_uri: `${issuerUrl}/certs` },
        ),
      );
    }) as never);
    let redirectDiscovery = true;
    const issuer = await listen(((req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => {
      if (req.url === "/certs" || redirectDiscovery) {
        res.writeHead(302, { Location: `${other.url}${req.url ?? ""}` }).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ issuer: issuerUrl, jwks_uri: `${issuerUrl}/certs` }));
    }) as never);
    issuerUrl = issuer.url;
    try {
      for (const discovery of [true, false]) {
        redirectDiscovery = discovery;
        const keys = new SigningKeys(issuer.url);
        await assert.rejects(keys.key("key-1"), KeysUnavailable, `redirect of the discovery document: ${discovery}`);
        assert.equal(keys.status(), "offline");
      }
      assert.deepEqual(reached, []);
    } finally {
      await Promise.all([other.close(), issuer.close()]);
    }
  });

  it("is offline until the first token", () => {
    const { keys } = setup();
    assert.equal(keys.status(), "offline");
  });
});
