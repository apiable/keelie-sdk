/**
 * The UUID rules the Python SDK gets from its standard library.
 *
 * {@link parseUuid} reads a UUID as Python's `uuid.UUID(str)` does, so the two
 * SDKs accept and refuse the same values. {@link uuid5} makes the same key from
 * the same namespace and name as Python's `uuid.uuid5`.
 *
 * @internal
 */

import { createHash } from "node:crypto";

const HEX = /^[0-9a-fA-F]{32}$/;

/** The UUID in its canonical form, lowercase with hyphens, or `null` if it is not one. */
export function parseUuid(value: unknown): string | null {
  if (typeof value !== "string") return null;
  // Python's order: drop "urn:" and "uuid:", the braces, then every hyphen.
  let hex = value.replaceAll("urn:", "").replaceAll("uuid:", "");
  hex = hex.replace(/^[{}]+|[{}]+$/g, "").replaceAll("-", "");
  if (!HEX.test(hex)) return null;
  hex = hex.toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The name-based UUID of RFC 9562, version 5 (SHA-1). */
export function uuid5(namespace: string, name: string): string {
  const ns = parseUuid(namespace);
  if (ns === null) throw new TypeError("namespace is not a UUID");
  const bytes = Buffer.from(ns.replaceAll("-", ""), "hex");
  const digest = createHash("sha1").update(bytes).update(name, "utf8").digest();
  digest[6] = (digest[6]! & 0x0f) | 0x50;
  digest[8] = (digest[8]! & 0x3f) | 0x80;
  const hex = digest.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
