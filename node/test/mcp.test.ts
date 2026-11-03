import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";

import type { KeelieFetch } from "../src/credential.js";
import { ProtectedResourceMetadata } from "../src/discovery.js";
import { mcpGuard } from "../src/express/index.js";
import { SigningKeys } from "../src/keys.js";
import { TokenVerifier } from "../src/tokens.js";
import { UsageReporter } from "../src/usage.js";
import { CONSUMER, FakeIssuer, ISSUER, ORG_ID, keyPair, listen, sign } from "./support.js";

const MCP = "https://api.example.com/mcp";
const pair = await keyPair("key-1");

describe("mcpGuard", () => {
  const issuer = new FakeIssuer(pair);
  const verifier = new TokenVerifier(ISSUER, MCP, ORG_ID, {
    keys: new SigningKeys(ISSUER, { fetch: issuer.fetch }),
  });
  const metadata = new ProtectedResourceMetadata(MCP, ISSUER);
  const events: Record<string, string>[] = [];
  const keelie: KeelieFetch = async (_path, init) => {
    events.push(...(JSON.parse(String(init?.body)) as { events: Record<string, string>[] }).events);
    return Response.json({}, { status: 202 });
  };
  const reporter = new UsageReporter(keelie, { batchSize: 1, flushIntervalSeconds: 0.02 });
  const seen: unknown[] = [];

  const app = express();
  app.use(
    mcpGuard({
      verifier,
      metadata,
      reporter,
      tools: { classify: "classify:run", delete_all: "admin" },
      maxBodyBytes: 4096,
    }),
  );
  // A body parser after the guard leaves the body it read alone.
  app.use(express.json());
  app.post("/mcp", async (req, res) => {
    seen.push(req.body);
    const server = new McpServer({ name: "product-classifier", version: "1.0.0" });
    server.registerTool("classify", { description: "Classify a product" }, async () => ({
      content: [{ type: "text", text: "Apparel > Shoes" }],
    }));
    server.registerTool("delete_all", { description: "Delete everything" }, async () => ({
      content: [{ type: "text", text: "gone" }],
    }));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  app.get("/mcp", (_req, res) => {
    res.status(405).set("Allow", "POST").end();
  });

  let url = "";
  let close = async () => {};
  let token = "";
  before(async () => {
    ({ url, close } = await listen(app as never));
    token = await sign(pair, { aud: MCP, scope: "classify:run", consumer_id: CONSUMER, azp: "claude" });
  });
  after(async () => {
    await reporter.close();
    await close();
  });

  const post = (body: string, auth = `Bearer ${token}`, method = "POST") =>
    fetch(`${url}/mcp`, {
      method,
      headers: {
        Authorization: auth,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      ...(method === "GET" || method === "HEAD" ? {} : { body }),
    });

  async function rpcError(response: Response, status: number, code: number, id: unknown = null) {
    assert.equal(response.status, status);
    assert.equal(response.headers.get("content-type"), "application/json");
    const body = (await response.json()) as { id: unknown; error: { code: number } };
    assert.equal(body.error.code, code);
    assert.equal(body.id, id);
  }

  it("lets a real MCP client list and call a tool its token allows, and counts the call", async () => {
    const client = new Client({ name: "agent", version: "1.0.0" });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${token}` } },
      }),
    );
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ["classify", "delete_all"]);
    const result = await client.callTool({ name: "classify", arguments: {} });
    assert.deepEqual(result.content, [{ type: "text", text: "Apparel > Shoes" }]);
    await assert.rejects(client.callTool({ name: "delete_all", arguments: {} }));
    await client.close();

    await new Promise((resolve) => setTimeout(resolve, 100));
    const calls = events.filter((e) => e["unit"] === "tool_call");
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!["capability_key"], "classify");
    assert.equal(calls[0]!["client_id"], "claude");
    assert.equal(calls[0]!["consumer_id"], CONSUMER);
    assert.equal(calls[0]!["credits"], undefined);
  });

  it("answers a tool its token lacks, or that is not mapped, with 403 and no scope named", async () => {
    for (const name of ["delete_all", "not_a_tool"]) {
      const response = await post(JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name } }));
      assert.equal(response.headers.get("www-authenticate"), metadata.challenge("insufficient_scope"));
      await rpcError(response, 403, -31001, 7);
    }
  });

  it("refuses what two parsers could read in two ways", async () => {
    await rpcError(
      await post('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify","name":"delete_all"}}'),
      400,
      -32600,
    );
    await rpcError(
      await post('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"classify","\\u006eame":"delete_all"}}'),
      400,
      -32600,
    );
    await rpcError(await post('[{"jsonrpc":"2.0","id":1,"method":"ping"}]'), 400, -32600);
    await rpcError(await post('"just a string"'), 400, -32600);
    await rpcError(await post("{not json"), 400, -32700);
    await rpcError(await post(`${"[".repeat(1001)}${"]".repeat(1001)}`), 400, -32700);
    await rpcError(await post('﻿{"jsonrpc":"2.0","id":1,"method":"ping"}'), 400, -32700);
  });

  it("refuses a tool call with no id, or a name that is not a string", async () => {
    await rpcError(await post('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"classify"}}'), 400, -32600);
    await rpcError(await post('{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"classify"}}'), 400, -32600);
    await rpcError(await post('{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":3}}'), 400, -32602, "a");
    await rpcError(await post('{"jsonrpc":"2.0","id":"a","method":"tools/call"}'), 400, -32602, "a");
  });

  it("refuses a body over the limit with 413", async () => {
    await rpcError(await post(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", pad: "x".repeat(5000) })), 413, -32600);
  });

  it("lets GET and DELETE pass, and refuses any other method with 405", async () => {
    assert.equal((await post("", undefined, "GET")).status, 405); // the server's own answer
    const put = await post("{}", undefined, "PUT");
    assert.equal(put.status, 405);
    assert.equal(put.headers.get("allow"), "GET, POST, DELETE");
  });

  it("checks the token first", async () => {
    const none = await fetch(`${url}/mcp`, { method: "POST", body: "{}" });
    assert.equal(none.status, 401);
    assert.equal(none.headers.get("www-authenticate"), metadata.challenge());
    const bad = await post("{}", "Bearer nope");
    assert.equal(bad.status, 401);
    assert.equal(bad.headers.get("www-authenticate"), metadata.challenge("invalid_token"));
  });

  it("hands the body it checked to the server", async () => {
    seen.length = 0;
    await post(JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "classify", arguments: {} } }));
    assert.deepEqual(seen, [{ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "classify", arguments: {} } }]);
  });
});
