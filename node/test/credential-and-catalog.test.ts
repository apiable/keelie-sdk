import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AiCatalog } from "../src/catalog.js";
import { sdkCredential, type KeelieFetch } from "../src/credential.js";
import { ProtectedResourceMetadata } from "../src/discovery.js";
import type { Fetch } from "../src/keys.js";
import { setLogger } from "../src/log.js";
import { Clock, ISSUER, RESOURCE } from "./support.js";

describe("sdkCredential", () => {
  it("mints a token once, sends it, and mints again on a 401", async () => {
    const calls: { url: string; auth: string | null; body: string }[] = [];
    let minted = 0;
    let refuse = false;
    const fetch: Fetch = async (url, init) => {
      const auth = new Headers(init?.headers).get("Authorization");
      calls.push({ url, auth, body: String(init?.body ?? "") });
      if (url === "https://issuer.example.com/token") {
        minted += 1;
        return Response.json({ access_token: `token-${minted}`, expires_in: 300 });
      }
      if (refuse) {
        refuse = false;
        return new Response(null, { status: 401 });
      }
      return Response.json({ ok: true });
    };
    const keelie = sdkCredential({
      keelieUrl: "https://keelie.example/",
      tokenUrl: "https://issuer.example.com/token",
      clientId: "sdk",
      clientSecret: "s3cret",
      fetch,
    });
    await Promise.all([keelie("/ai-catalog"), keelie("/ai-catalog")]);
    assert.equal(minted, 1);
    assert.equal(
      calls[0]!.body,
      "grant_type=client_credentials&client_id=sdk&client_secret=s3cret",
    );
    assert.deepEqual(
      calls.slice(1).map((c) => [c.url, c.auth]),
      [
        ["https://keelie.example/ai-catalog", "Bearer token-1"],
        ["https://keelie.example/ai-catalog", "Bearer token-1"],
      ],
    );
    refuse = true;
    const response = await keelie("/usage-events:report", { method: "POST", body: "{}" });
    assert.equal(response.status, 200);
    assert.equal(minted, 2);
    assert.equal(calls.at(-1)!.auth, "Bearer token-2");
    assert.equal(calls.at(-1)!.body, "{}");
  });

  it("fails when the token endpoint refuses", async () => {
    const keelie = sdkCredential({
      keelieUrl: "https://keelie.example",
      tokenUrl: "https://issuer.example.com/token",
      clientId: "sdk",
      clientSecret: "wrong",
      fetch: async () => new Response(null, { status: 401 }),
    });
    await assert.rejects(keelie("/ai-catalog"));
  });
});

describe("AiCatalog", () => {
  const document = '{"specVersion":"0.91","entries":[]}';

  function setup() {
    const clock = new Clock();
    let answers: (number | "network")[] = [];
    let fetched = 0;
    const keelie: KeelieFetch = async (path) => {
      assert.equal(path, "/ai-catalog");
      fetched += 1;
      const answer = answers.shift() ?? 200;
      if (answer === "network") throw new TypeError("fetch failed");
      return new Response(answer === 200 ? document : null, { status: answer });
    };
    const metadata = new ProtectedResourceMetadata(RESOURCE, ISSUER);
    const catalog = new AiCatalog(keelie, metadata, { clock: clock.read });
    return {
      clock,
      metadata,
      catalog,
      fetched: () => fetched,
      fail: (...next: (number | "network")[]) => {
        answers = next;
      },
    };
  }

  it("tells the guards that its paths need no token", () => {
    const { metadata } = setup();
    assert.equal(metadata.aiCatalog, true);
  });

  it("serves one body at both paths, with their media types, and keeps it 60 seconds", async () => {
    const { catalog, clock, fetched } = setup();
    const ard = await catalog.answer("/.well-known/ard.json");
    const ai = await catalog.answer("/.well-known/ai-catalog.json");
    assert.equal(ard!.status, 200);
    assert.equal(ard!.headers["Content-Type"], "application/json");
    assert.equal(ai!.headers["Content-Type"], "application/ai-catalog+json");
    assert.equal(ai!.headers["Cache-Control"], "max-age=60");
    assert.equal(new TextDecoder().decode(ai!.body), document);
    assert.equal(fetched(), 1);
    clock.now += 59;
    await catalog.answer("/.well-known/ard.json");
    assert.equal(fetched(), 1);
    clock.now += 1;
    await catalog.answer("/.well-known/ard.json");
    assert.equal(fetched(), 2);
    assert.equal(await catalog.answer("/other"), null);
  });

  it("answers 503 when keelie fails, never an old copy, and asks again after 10 seconds", async () => {
    setLogger({ debug() {}, info() {}, warn() {} });
    const { catalog, clock, fetched, fail } = setup();
    await catalog.answer("/.well-known/ard.json");
    clock.now += 60;
    fail(500);
    const down = await catalog.answer("/.well-known/ard.json");
    assert.equal(down!.status, 503);
    assert.equal(down!.headers["Retry-After"], "10");
    assert.equal(down!.headers["Cache-Control"], "no-store");
    clock.now += 9;
    assert.equal((await catalog.answer("/.well-known/ard.json"))!.status, 503);
    assert.equal(fetched(), 2);
    clock.now += 1;
    assert.equal((await catalog.answer("/.well-known/ard.json"))!.status, 200);
    assert.equal(fetched(), 3);
    setLogger(undefined);
  });

  it("makes one fetch for many requests at once", async () => {
    const { catalog, fetched } = setup();
    await Promise.all(Array.from({ length: 10 }, () => catalog.answer("/.well-known/ard.json")));
    assert.equal(fetched(), 1);
  });
});
