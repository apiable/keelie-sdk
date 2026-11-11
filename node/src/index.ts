/**
 * The Keelie SDK, by Apiable. In development, not released.
 *
 * Source: https://github.com/apiable/keelie-sdk
 *
 * It verifies tokens inside your own process, against the issuer's key set,
 * which it fetches and caches, and checks their scope against the route. It
 * reports usage in batches, in the background. It does not sit in the request
 * path. It serves the RFC 9728 metadata that tells an agent where to get a
 * token, and your AI Catalog, which keelie builds from your published plans.
 *
 * This module is the core, with no framework in it. The Express adapters, for a
 * REST API and for an MCP server, are in `keelie/express`.
 */

export { AiCatalog, type AiCatalogOptions, type CatalogAnswer } from "./catalog.js";
export { sdkCredential, type KeelieFetch, type SdkCredentialOptions } from "./credential.js";
export {
  ProtectedResourceMetadata,
  bearerToken,
  type ProtectedResourceMetadataOptions,
} from "./discovery.js";
export { SigningKeys, type Fetch, type SigningKeysOptions, type Status } from "./keys.js";
export { setLogger, type Logger } from "./log.js";
export { InsufficientScope, ScopeMap } from "./scopes.js";
export {
  TokenRejected,
  TokenVerifier,
  type Claims,
  type Reason,
  type TokenVerifierOptions,
} from "./tokens.js";
export {
  KEELIE_OUTCOME_NAMESPACE,
  UsageReporter,
  type Amount,
  type RecordOptions,
  type Unit,
  type UsageReporterOptions,
} from "./usage.js";

export const VERSION = "0.0.2";
