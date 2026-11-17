// The example of docs/node.md, "Get started with Express". It is compiled with the tests, and
// never run, so the example cannot drift from the package. Keep the two the same.

import express from "express";
import {
  ProtectedResourceMetadata,
  ScopeMap,
  TokenVerifier,
  UsageReporter,
  sdkCredential,
} from "../src/index.js";
import { scopeGuard, tokenGuard } from "../src/express/index.js";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const keelie = sdkCredential({
  keelieUrl: env("KEELIE_URL"),
  tokenUrl: env("KEELIE_TOKEN_URL"),
  clientId: env("KEELIE_SDK_CLIENT_ID"),
  clientSecret: env("KEELIE_SDK_CLIENT_SECRET"),
});
const verifier = new TokenVerifier(env("KEELIE_ISSUER"), env("KEELIE_RESOURCE"), env("KEELIE_ORG_ID"));
const metadata = new ProtectedResourceMetadata(env("KEELIE_RESOURCE"), env("KEELIE_ISSUER"));
const scopes = new ScopeMap({ "GET /v1/orders/:orderId": "orders:read" });
const reporter = new UsageReporter(keelie);

const app = express();
app.use(tokenGuard({ verifier, metadata }));

app.get("/v1/orders/:orderId", scopeGuard(scopes, metadata), (req, res) => {
  const claims = req.keelieClaims!;
  reporter.record(claims.azp, "GET /v1/orders/:orderId", {
    credits: 1,
    consumerId: claims.consumerId,
  });
  res.json({ orderId: req.params.orderId });
});

const server = app.listen(3000);
process.on("SIGTERM", async () => {
  server.close();
  await reporter.close();
});
