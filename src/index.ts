/**
 * Mandate Protocol reference implementation.
 * Subpath entry points: mandate-protocol/agent, /verifier, /registry, /proxy, /adapters, /evidence.
 */
export * from './core/types.js';
export { generateKey, keyFromSeed, thumbprint, publicOf, parseKeyFile, signBytes, verifyBytes } from './core/keys.js';
export { issueMandate, decodeMandate, verifyMandateSignature, type IssueOptions, type DecodedMandate } from './core/mandate.js';
export { signRequest, parseSignature, verifySignature, type SignOptions, type SignedHeaders } from './core/signature.js';
export { contentDigest, checkContentDigest } from './core/digest.js';
export { evaluatePolicy, estimateNotional, isExit, combine, type PolicyResult, type Usage } from './core/policy.js';
export { canonicalJson, b64u } from './core/encoding.js';
export { MandateAgent, createAgent, type AgentOptions } from './agent/index.js';
export { Verifier, createVerifier, MemoryState, type VerifierOptions, type VerifyResult, type StateStore, type ContextArgs } from './verifier/index.js';
export { mandateMiddleware, verifyFetchRequest, type MiddlewareOptions } from './verifier/middleware.js';
export { StaticRegistry, chainResolvers } from './registry/static.js';
export { RegistryClient } from './registry/client.js';
export type { Resolver } from './registry/types.js';
export { alpacaAdapter, mcpAdapter, genericAdapter, classify, type OrderAdapter } from './adapters/index.js';
export { EvidenceLog, verifyChain, readLog, type EvidenceEntry } from './evidence/index.js';
export { VERSION } from './version.js';
