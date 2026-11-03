import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ProtectedResourceMetadata, bearerToken } from "../src/discovery.js";
import { InsufficientScope, ScopeMap } from "../src/scopes.js";
import type { Claims } from "../src/tokens.js";
import { ISSUER } from "./support.js";

function claims(...scopes: string[]): Claims {
  return {
    azp: "client",
    orgId: "6c7a6f0e-4a8b-4c2d-9a51-0b3e5d7f9a12",
    scopes: new Set(scopes),
    jti: null,
    expiresAt: new Date(),
    consumerId: null,
  };
}

describe("ScopeMap", () => {
  const scopes = new ScopeMap({
    "GET /orders/:orderId": "orders:read",
    "post /orders": "orders:write",
  });

  it("passes a token with the route's scope", () => {
    scopes.check(claims("orders:read"), "get", "/orders/:orderId");
    scopes.check(claims("orders:write"), "POST", "/orders");
  });

  it("matches a scope and a route only to themselves", () => {
    assert.throws(() => scopes.check(claims("orders"), "GET", "/orders/:orderId"), InsufficientScope);
    assert.throws(() => scopes.check(claims("orders:read:all"), "GET", "/orders/:orderId"), InsufficientScope);
    assert.throws(() => scopes.check(claims("orders:read"), "GET", "/orders/:orderId/items"), InsufficientScope);
    assert.throws(() => scopes.check(claims("orders:read"), "HEAD", "/orders/:orderId"), InsufficientScope);
    assert.throws(() => scopes.check(claims("orders:read"), "GET", "/unmapped"), InsufficientScope);
  });

  it("refuses a map that is not one scope a route", () => {
    assert.throws(() => new ScopeMap({ "GET /a": "two scopes" }), TypeError);
    assert.throws(() => new ScopeMap({ "GET /a": "" }), TypeError);
    assert.throws(() => new ScopeMap({ "/a": "s" }), TypeError);
    assert.throws(() => new ScopeMap({ "GET /a": "s", "get /a": "t" }), TypeError);
  });
});

describe("ProtectedResourceMetadata", () => {
  it("serves the metadata between the host and the path", () => {
    const metadata = new ProtectedResourceMetadata("https://api.example.com/v1", ISSUER, {
      scopesSupported: ["orders:read"],
    });
    assert.equal(metadata.path, "/.well-known/oauth-protected-resource/v1");
    assert.equal(metadata.url, "https://api.example.com/.well-known/oauth-protected-resource/v1");
    assert.equal(
      metadata.document,
      '{"resource":"https://api.example.com/v1","authorization_servers":["https://issuer.example.com/realms/portal-labs"],"bearer_methods_supported":["header"],"scopes_supported":["orders:read"]}',
    );
    assert.equal(metadata.challenge(), `Bearer resource_metadata="${metadata.url}"`);
    assert.equal(
      metadata.challenge("invalid_token"),
      `Bearer error="invalid_token", resource_metadata="${metadata.url}"`,
    );
    assert.throws(() => metadata.challenge('x", evil="1'), TypeError);
    assert.ok(metadata.protects("/v1"));
    assert.ok(metadata.protects("/v1/orders"));
    assert.ok(!metadata.protects("/v10"));
    assert.ok(!metadata.protects("/health"));
  });

  it("protects every path for a resource at the root", () => {
    for (const resource of ["https://api.example.com", "https://api.example.com/"]) {
      const metadata = new ProtectedResourceMetadata(resource, ISSUER);
      assert.equal(metadata.path, "/.well-known/oauth-protected-resource");
      assert.ok(metadata.protects("/anything"));
    }
  });

  it("takes only a plain lowercase https URL", () => {
    for (const bad of [
      "http://api.example.com",
      "https://API.example.com",
      "HTTPS://api.example.com",
      "https://api.example.com/v1/",
      "https://api.example.com/v1?x=1",
      "https://api.example.com/v1#x",
      "https://user@api.example.com",
      "https://api.example.com:http",
      "https://api.example.com:70000",
      "https:///v1",
      'https://api.example.com/"',
      "https://api.example.com/a b",
    ]) {
      assert.throws(() => new ProtectedResourceMetadata(bad, ISSUER), TypeError, bad);
    }
    new ProtectedResourceMetadata("https://api.example.com:8443/mcp", ISSUER);
    assert.throws(
      () => new ProtectedResourceMetadata("https://api.example.com", ISSUER, { scopesSupported: "a b" }),
      TypeError,
    );
  });
});

describe("bearerToken", () => {
  it("reads the token of a Bearer header and nothing else", () => {
    assert.equal(bearerToken("Bearer abc"), "abc");
    assert.equal(bearerToken("bearer   abc  "), "abc");
    assert.equal(bearerToken("Basic abc"), null);
    assert.equal(bearerToken("Bearer"), null);
    assert.equal(bearerToken("Bearer "), null);
    assert.equal(bearerToken(undefined), null);
  });
});
