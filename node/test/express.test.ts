import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

import express5 from "express";
import express4 from "express4";

import { AiCatalog } from "../src/catalog.js";
import { ProtectedResourceMetadata } from "../src/discovery.js";
import { aiCatalog, scopeGuard, tokenGuard } from "../src/express/index.js";
import { SigningKeys } from "../src/keys.js";
import { ScopeMap } from "../src/scopes.js";
import { TokenVerifier } from "../src/tokens.js";
import { FakeIssuer, ISSUER, ORG_ID, RESOURCE, keyPair, listen, sign } from "./support.js";

const pair = await keyPair("key-1");

for (const [name, express] of [
  ["Express 5", express5],
  ["Express 4", express4 as unknown as typeof express5],
] as const) {
  describe(`tokenGuard and scopeGuard, ${name}`, () => {
    const issuer = new FakeIssuer(pair);
    const verifier = new TokenVerifier(ISSUER, RESOURCE, ORG_ID, {
      keys: new SigningKeys(ISSUER, { fetch: issuer.fetch }),
    });
    const metadata = new ProtectedResourceMetadata(RESOURCE, ISSUER);
    const scopes = new ScopeMap({
      "GET /v1/orders/:orderId": "orders:read",
      "POST /v1/orders": "orders:write",
      "GET /v1/items/:itemId": "items:read",
    });
    const catalog = new AiCatalog(async () => Response.json({ entries: [] }), metadata);
    const app = express();
    app.use(aiCatalog(catalog));
    app.use(tokenGuard({ verifier, metadata }));
    app.get("/health", (_req, res) => {
      res.json({ ok: true });
    });
    app.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), (req, res) => {
      res.json({ orderId: req.params["orderId"], azp: req.keelieClaims?.azp });
    });
    app.post("/v1/orders", scopeGuard(scopes, metadata), (_req, res) => {
      res.status(201).json({});
    });
    app.get("/v1/unmapped", scopeGuard(scopes, metadata), (_req, res) => {
      res.json({});
    });
    const router = express.Router();
    router.get("/items/:itemId", scopeGuard(scopes, metadata), (_req, res) => {
      res.json({ item: true });
    });
    app.use("/v1", router);
    app.get("/v1/no-claims-check", (req, res) => {
      res.json({ claims: req.keelieClaims !== undefined });
    });

    let url = "";
    let close = async () => {};
    let token = "";
    before(async () => {
      ({ url, close } = await listen(app as never));
      token = await sign(pair);
    });
    after(() => close());

    const get = (path: string, auth?: string, method = "GET") =>
      fetch(`${url}${path}`, { method, headers: auth ? { Authorization: auth } : {} });

    it("serves the metadata with no token", async () => {
      const response = await get("/.well-known/oauth-protected-resource/v1");
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), "application/json");
      assert.equal(await response.text(), metadata.document);
      const head = await get("/.well-known/oauth-protected-resource/v1", undefined, "HEAD");
      assert.equal(head.status, 200);
    });

    it("refuses a request with no token, and names the metadata", async () => {
      const response = await get("/v1/orders/42");
      assert.equal(response.status, 401);
      assert.equal(response.headers.get("www-authenticate"), metadata.challenge());
      assert.equal(await response.text(), "");
    });

    it("refuses a bad token the same way for every reason", async () => {
      for (const bad of ["Bearer nope", `Bearer ${await sign(pair, { org_id: "0f2e1d3c-5b4a-4968-8776-a5b4c3d2e1f0" })}`]) {
        const response = await get("/v1/orders/42", bad);
        assert.equal(response.status, 401);
        assert.equal(response.headers.get("www-authenticate"), metadata.challenge("invalid_token"));
        assert.equal(await response.text(), "");
      }
    });

    it("gives the claims to a route whose scope the token carries", async () => {
      const response = await get("/v1/orders/42", `Bearer ${token}`);
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { orderId: "42", azp: "consumer-client" });
    });

    it("answers 403 to a route whose scope the token lacks, or that is not in the map", async () => {
      for (const [path, method] of [
        ["/v1/orders", "POST"],
        ["/v1/unmapped", "GET"],
      ] as const) {
        const response = await get(path, `Bearer ${token}`, method);
        assert.equal(response.status, 403, path);
        assert.equal(response.headers.get("www-authenticate"), metadata.challenge("insufficient_scope"));
      }
    });

    it("reads the template of a route in a mounted router", async () => {
      const refused = await get("/v1/items/7", `Bearer ${token}`);
      assert.equal(refused.status, 403);
      const allowed = await get("/v1/items/7", `Bearer ${await sign(pair, { scope: "items:read" })}`);
      assert.equal(allowed.status, 200);
    });

    it("lets paths outside resource, and a preflight, pass untouched", async () => {
      assert.equal((await get("/health")).status, 200);
      assert.notEqual((await get("/v1/orders/42", undefined, "OPTIONS")).status, 401);
    });

    it("guards every form of a path Express would route", async () => {
      for (const path of ["/V1/orders/42", "/v1/../v1/orders/42", "/%76%31/orders/42", "//v1/orders/42", "/x/..%2fv1/orders/42"]) {
        const response = await get(path);
        assert.ok(response.status === 401 || response.status === 404, `${path}: ${response.status}`);
        assert.notEqual(response.status, 200, path);
      }
      // The router does serve the uppercase form, and the guard refuses it.
      assert.equal((await get("/V1/orders/42")).status, 401);
    });

    it("serves the AI Catalog with no token", async () => {
      const response = await get("/.well-known/ai-catalog.json");
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), "application/ai-catalog+json");
      assert.deepEqual(await response.json(), { entries: [] });
    });

    it("fails a route whose scopeGuard has no tokenGuard before it", async () => {
      const bare = express();
      bare.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), (_req, res) => {
        res.json({});
      });
      const server = await listen(bare as never);
      const response = await fetch(`${server.url}/v1/orders/1`);
      assert.equal(response.status, 500);
      await server.close();
    });
  });
}

describe("the guards", () => {
  it("do not start when the verifier's audience is not the resource", () => {
    const verifier = new TokenVerifier(ISSUER, "https://api.example.com/v2", ORG_ID);
    const metadata = new ProtectedResourceMetadata(RESOURCE, ISSUER);
    assert.throws(() => tokenGuard({ verifier, metadata }), TypeError);
  });
});
