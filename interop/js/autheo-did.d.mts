// Type declarations for autheo-did.mjs (the main public surface; documents are plain JSON objects).
// verify-venue-vectors.mjs checks that every name exported here exists at runtime.

export type Json = Record<string, any>;
export interface ChainError { index: number; code: string; detail: string }
export interface ChainLink { index: number; id: string; digest: string; issuer: string; subject: string; valid_from: string; valid_until: string }
export interface Capability {
  environments: string[]; scopes: string[]; resources: string[]; tools: string[]; asset: string;
  per_action_minor: number; total_budget_minor: number; approval_threshold_minor: number; max_delegation_depth: number;
}
export interface ChainResult {
  at: number; valid: boolean; authentic: boolean; errors: ChainError[]; links: ChainLink[];
  root: string | null; leaf: string | null; capability: Capability | null; ignoredRevocations: number;
}
export interface InvocationResult { invocation: Json; chain: ChainResult; digest: string; created: number; expires: number }
export interface VerifyOptions {
  at?: number; trustedRoots?: string[] | null; revocations?: Json[]; skew?: number; documents?: Record<string, Json>;
}
export interface Decision { decision: "allow" | "escalate" | "block"; reasons: string[]; policy_id: string; policy_digest: string }
export interface BundleReport {
  valid: boolean; verdict?: string; problems: string[]; decision?: string; reasons?: string[]; invoker?: string;
  root?: string | null; requestId?: string; authorizedByChain?: boolean; requestProblems?: string[]; chain?: ChainResult;
}
export interface ReceiptsReport { valid: boolean; count: number; head: string; firstInvalidSequence: number | null; problems: { sequence: number; problem: string }[]; anchorMatches: boolean | null }

export declare const VC_CONTEXT: string;
export declare const CLOCK_SKEW_SECONDS: number;
export declare const MAX_CHAIN_LENGTH: number;
export declare const MAX_INVOCATION_SECONDS: number;
export declare const ZERO_HASH: string;
export declare const SCOPES: string[];
export declare const SCOPE_ALIASES: Record<string, string>;
export declare function canonicalScope(scope: string): string;
export declare function hasScope(granted: string[], scope: string): boolean;
export declare const MANDATE_ONLY_POLICY: { policy_id: string; policy_digest: string };
export declare class AutheoError extends Error { code: string; constructor(code: string, detail?: string) }

export declare function hex(bytes: Uint8Array): string;
export declare function fromHex(text: string): Uint8Array;
export declare function jcs(value: unknown): string;
export declare function digest(value: unknown): Promise<string>;
export declare function parseTime(value: string): number;
export declare function formatTime(epoch: number): string;
export declare function didFromSeed(seed: Uint8Array): Promise<string>;
export declare function publicFromDidKey(did: string): Uint8Array;
export declare function signDocument(document: Json, seed: Uint8Array, purpose: string, createdEpoch: number): Promise<Json>;
export declare function verifyProof(secured: Json, purpose: string, documents?: Record<string, Json>): Promise<{ controller: string }>;
export declare function patternMatches(pattern: string, value: string | null | undefined): boolean;
export declare function attenuationProblems(parent: Json, child: Json): string[];
export declare function capabilityProblems(capability: Json, request: Json): string[];
export declare function verifyRevocation(record: Json, documents?: Record<string, Json>): Promise<Json>;
export declare function verifyChain(chain: Json[], options?: VerifyOptions): Promise<ChainResult>;
export declare function verifyInvocation(invocation: Json, options?: VerifyOptions): Promise<InvocationResult>;
export declare function decideInvocation(result: InvocationResult, options: { environment: string; history?: Json[] }): Decision;
export declare function signDecisionReceipt(result: InvocationResult, decision: Decision, seed: Uint8Array, environment: string,
  at: { id: string; sequence: number; previousHash: string; recordedAt: number }): Promise<Json>;
export declare function verifyReceipt(receipt: Json, issuer?: string | null, documents?: Record<string, Json>): Promise<Json>;
export declare function chainHash(previousHash: string, receipt: Json): Promise<string>;
export declare function verifyReceipts(receipts: Json[], options?: { issuer?: string | null; environment?: string | null; expectedHead?: string | null; documents?: Record<string, Json> }): Promise<ReceiptsReport>;
export declare function verifyBundle(bundle: Json, options?: VerifyOptions & { environmentDid?: string | null }): Promise<BundleReport>;
