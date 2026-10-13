// Autheo v2 verifier/signer: did:key, RFC 8785 JCS, eddsa-jcs-2022 Data Integrity proofs,
// delegation chains, invocations, revocations, decision bundles and v2 ledger exports.
//
// Dependency-free and isomorphic: uses only globalThis.crypto.subtle (Ed25519 + SHA-256),
// so the same file runs in Node >= 20 and in current browsers (the web demo serves a copy).
// Normative text: docs/SPEC-DID.md. Checked against tests/vectors/autheo-v2-vectors.json
// by verify-v2-vectors.mjs. Everything here works offline: did:key is resolved locally and
// did:web only from a caller-supplied documents map.

const subtle = globalThis.crypto && globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const CLOCK_SKEW_SECONDS = 2;
export const MAX_CHAIN_LENGTH = 10;
export const MAX_DELEGATION_SECONDS = 30 * 86400;
export const MAX_INVOCATION_SECONDS = 300;
export const ZERO_HASH = '0'.repeat(64);
export const SCOPES = ['marketplace.read', 'devhub.read', 'chain.read', 'compute.simulate', 'environment.handoff',
  'tool.invoke', 'model.invoke', 'file.read', 'file.write', 'network.fetch', 'message.send', 'task.checkpoint',
  'dex.quote', 'dex.policy_check', 'dex.order.build', 'dex.order.request_signature', 'dex.order.sign'];
// dex.order.sign: deprecated alias of dex.order.request_signature (0.7), removed in 0.8; compare through hasScope.
export const SCOPE_ALIASES = { 'dex.order.sign': 'dex.order.request_signature' };
export const canonicalScope = (scope) => SCOPE_ALIASES[scope] || scope;
export const hasScope = (granted, scope) => granted.some((s) => canonicalScope(s) === canonicalScope(scope));
// The built-in policy (autheo.policy/v1 "policy:mandate-only"); decideInvocation implements exactly this one.
export const MANDATE_ONLY_POLICY = { policy_id: 'policy:mandate-only',
  policy_digest: 'c1d174b4667b64276d85da3bf911416d1125032f942746c55c97922dcfcafcb4' };
export const AUTHENTICITY_ERRORS = new Set(['malformed', 'bad_signature', 'broken_link', 'chain_too_long',
  'invoker_mismatch']);
const RELATIONSHIPS = ['authentication', 'assertionMethod', 'capabilityDelegation', 'capabilityInvocation'];
const PROOF_MEMBERS = new Set(['type', 'cryptosuite', 'created', 'verificationMethod', 'proofPurpose', 'proofValue',
  '@context']);

export const PATTERNS = {
  identifier: /^[A-Za-z0-9][A-Za-z0-9:._-]{0,95}$/,
  asset: /^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$/,
  tool: /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/,
  reason: /^[a-z][a-z0-9_]*(:[A-Za-z0-9:._-]{1,96})?$/,
  hex64: /^[0-9a-f]{64}$/,
  did: /^did:(key|web):[A-Za-z0-9._:-]{1,88}$/,
  didUrl: /^did:(key|web):[A-Za-z0-9._:-]{1,88}#[A-Za-z0-9._~:-]{1,128}$/,
  urn: /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  dateTime: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/,
  grant: /^(\*|[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\*?)$/,
  proofValue: /^z[1-9A-HJ-NP-Za-km-z]{80,96}$/,
  revocationReason: /^[a-z][a-z0-9_]{0,63}$/,
};

export class AutheoError extends Error {
  constructor(code, detail) { super(detail ? code + ': ' + detail : code); this.code = code; }
}

// ------------------------------------------------------------------ bytes, base58, varint
export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (text) => new Uint8Array((text.match(/../g) || []).map((h) => parseInt(h, 16)));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function b58encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  let number = 0n;
  for (const byte of bytes) number = number * 256n + BigInt(byte);
  let out = '';
  while (number > 0n) { out = ALPHABET[Number(number % 58n)] + out; number /= 58n; }
  return '1'.repeat(zeros) + out;
}

export function b58decode(text) {
  // 8192 fits ML-DSA-87 signatures (mirrors multibase.MAX_ENCODED).
  if (typeof text !== 'string' || text.length > 8192) throw new AutheoError('invalid_base58');
  let number = 0n;
  for (const character of text) {
    const value = ALPHABET.indexOf(character);
    if (value < 0) throw new AutheoError('invalid_base58');
    number = number * 58n + BigInt(value);
  }
  const body = [];
  while (number > 0n) { body.unshift(Number(number % 256n)); number /= 256n; }
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros += 1;
  return new Uint8Array([...new Array(zeros).fill(0), ...body]);
}

export function varintEncode(value) {
  const out = [];
  let rest = BigInt(value);
  do {
    let byte = Number(rest & 0x7fn);
    rest >>= 7n;
    if (rest > 0n) byte |= 0x80;
    out.push(byte);
  } while (rest > 0n);
  return new Uint8Array(out);
}

export function varintDecode(bytes) {
  let value = 0;
  let shift = 0;
  for (let i = 0; i < Math.min(bytes.length, 9); i += 1) {
    value += (bytes[i] & 0x7f) * 2 ** shift;
    if (!(bytes[i] & 0x80)) {
      if (i > 0 && bytes[i] === 0) throw new AutheoError('invalid_varint', 'non-minimal');
      return [value, i + 1];
    }
    shift += 7;
  }
  throw new AutheoError('invalid_varint', 'truncated');
}

export const multibaseEncode = (bytes) => 'z' + b58encode(bytes);
export function multibaseDecode(text) {
  if (typeof text !== 'string' || !text.startsWith('z') || text.length < 2) {
    throw new AutheoError('invalid_multibase', 'only base58btc');
  }
  return b58decode(text.slice(1));
}

// ------------------------------------------------------------------ did:key
export function publicKeyMultibase(raw) {
  if (raw.length !== 32) throw new AutheoError('invalidPublicKeyLength');
  return multibaseEncode(concat(new Uint8Array([0xed, 0x01]), raw));
}
export const didKeyFromPublic = (raw) => 'did:key:' + publicKeyMultibase(raw);

export function decodePublicMultibase(value) {
  const bytes = multibaseDecode(value);
  const [code, used] = varintDecode(bytes);
  if (code !== 0xed) throw new AutheoError('unsupportedPublicKeyType');
  const raw = bytes.slice(used);
  if (raw.length !== 32) throw new AutheoError('invalidPublicKeyLength');
  return raw;
}

export function publicFromDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:')) throw new AutheoError('invalidDid');
  const parts = did.split(':');
  if (parts.length !== 3 || !parts[2].startsWith('z')) throw new AutheoError('invalidDid');
  let raw;
  try { raw = decodePublicMultibase(parts[2]); } catch (error) { throw new AutheoError('invalidDid', error.code); }
  if (didKeyFromPublic(raw) !== did) throw new AutheoError('invalidDid', 'non-canonical');
  return raw;
}

export function didKeyDocument(did) {
  publicFromDidKey(did);
  const fingerprint = did.split(':')[2];
  const id = did + '#' + fingerprint;
  const document = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [{ id, type: 'Multikey', controller: did, publicKeyMultibase: fingerprint }],
  };
  for (const relationship of RELATIONSHIPS) document[relationship] = [id];
  return document;
}

export function didWebUrl(did) {
  if (typeof did !== 'string' || !/^did:web:[A-Za-z0-9.-]+(%3A[0-9]{1,5})?(:[A-Za-z0-9._~%-]+)*$/.test(did)) {
    throw new AutheoError('invalidDid');
  }
  const parts = did.split(':').slice(2);
  const host = decodeURIComponent(parts[0]);
  const path = parts.slice(1).map(decodeURIComponent).join('/');
  if (parts.slice(1).some((s) => s === '' || s === '.' || s === '..')) throw new AutheoError('invalidDid');
  return path ? 'https://' + host + '/' + path + '/did.json' : 'https://' + host + '/.well-known/did.json';
}

// Resolve (controller DID, raw Ed25519 key) for a verification method + relationship. Offline only:
// did:key locally, did:web only from options.documents ({did: document}).
export function resolveKey(verificationMethod, relationship, documents = {}) {
  if (!RELATIONSHIPS.includes(relationship)) throw new AutheoError('invalidProofPurpose');
  if (typeof verificationMethod !== 'string' || !verificationMethod.includes('#')) {
    throw new AutheoError('invalidVerificationMethod');
  }
  const did = verificationMethod.split('#')[0];
  let document;
  if (did.startsWith('did:key:')) document = didKeyDocument(did);
  else if (did.startsWith('did:web:')) {
    didWebUrl(did);
    document = documents[did];
    if (!document) throw new AutheoError('notFound', 'did:web document not supplied (offline)');
    if (document.id !== did) throw new AutheoError('invalidDidDocument');
  } else throw new AutheoError('methodNotSupported');
  const absolute = (ref) => (typeof ref === 'string' && ref.startsWith('#') ? did + ref : ref);
  const methods = {};
  for (const method of document.verificationMethod || []) {
    if (method && typeof method.id === 'string') methods[absolute(method.id)] = method;
  }
  let authorised = false;
  for (const entry of document[relationship] || []) {
    if (typeof entry === 'string' && absolute(entry) === verificationMethod) authorised = true;
    else if (entry && typeof entry === 'object' && absolute(entry.id || '') === verificationMethod) {
      authorised = true; methods[verificationMethod] = entry;
    }
  }
  const method = methods[verificationMethod];
  if (!authorised || !method) throw new AutheoError('invalidVerificationMethod');
  if (method.controller !== did) throw new AutheoError('invalidVerificationMethod', 'controller');
  if ((method.type === 'Multikey' || method.type === 'Ed25519VerificationKey2020')
      && typeof method.publicKeyMultibase === 'string') {
    return [did, decodePublicMultibase(method.publicKeyMultibase)];
  }
  if ((method.type === 'JsonWebKey' || method.type === 'JsonWebKey2020') && method.publicKeyJwk) {
    const jwk = method.publicKeyJwk;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || 'd' in jwk) throw new AutheoError('unsupportedPublicKeyType');
    const raw = fromBase64Url(jwk.x || '');
    if (raw.length !== 32) throw new AutheoError('invalidPublicKeyLength');
    return [did, raw];
  }
  throw new AutheoError('unsupportedPublicKeyType');
}

const toBase64Url = (bytes) => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const fromBase64Url = (text) => {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
};

// ------------------------------------------------------------------ RFC 8785 JCS (Autheo profile)
const utf16Compare = (a, b) => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
};

function jcsString(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new AutheoError('jcs', 'lone surrogate');
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new AutheoError('jcs', 'lone surrogate');
  }
  return JSON.stringify(value);
}

export function jcs(value, depth = 0) {
  if (depth > 32) throw new AutheoError('jcs', 'too deep');
  if (value === null || value === true || value === false) return String(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new AutheoError('jcs', 'safe integers only');
    return String(value);
  }
  if (typeof value === 'string') return jcsString(value);
  if (Array.isArray(value)) return '[' + value.map((v) => jcs(v, depth + 1)).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort(utf16Compare);
    return '{' + keys.map((k) => jcsString(k) + ':' + jcs(value[k], depth + 1)).join(',') + '}';
  }
  throw new AutheoError('jcs', 'unsupported value');
}

export const jcsBytes = (value) => encoder.encode(jcs(value));
export async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }
export async function digest(value) { return hex(await sha256(jcsBytes(value))); }

// ------------------------------------------------------------------ time
export function parseTime(value) {
  if (typeof value !== 'string' || !PATTERNS.dateTime.test(value)) throw new AutheoError('bad_time');
  const ms = Date.parse(value);
  if (Number.isNaN(ms) || new Date(ms).toISOString().replace('.000Z', 'Z') !== value) {
    throw new AutheoError('bad_time');
  }
  return ms / 1000;
}
export const formatTime = (epoch) => new Date(epoch * 1000).toISOString().replace('.000Z', 'Z');

// ------------------------------------------------------------------ structural checks (mirror models_v2.py)
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v, min, max) => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const MINOR_MAX = 1e15;

function fields(value, allowed, required, where) {
  if (!isObject(value)) throw new AutheoError('malformed', where + ' must be an object');
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new AutheoError('malformed', where + '.' + key);
  for (const key of required) if (!(key in value)) throw new AutheoError('malformed', where + '.' + key + ' missing');
}
function str(value, pattern, where) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new AutheoError('malformed', where);
}
function list(value, min, max, item, where) {
  if (!Array.isArray(value) || value.length < min || value.length > max) throw new AutheoError('malformed', where);
  value.forEach((v, i) => item(v, where + '.' + i));
}
function unique(value, where) {
  if (new Set(value).size !== value.length) throw new AutheoError('malformed', where + ' items must be unique');
}
function literal(value, expected, where) {
  if (value !== expected) throw new AutheoError('malformed', where);
}

export function checkProof(proof, purpose, where = 'proof') {
  fields(proof, [...PROOF_MEMBERS], ['type', 'cryptosuite', 'created', 'verificationMethod', 'proofPurpose',
    'proofValue'], where);
  literal(proof.type, 'DataIntegrityProof', where + '.type');
  literal(proof.cryptosuite, 'eddsa-jcs-2022', where + '.cryptosuite');
  str(proof.created, PATTERNS.dateTime, where + '.created');
  str(proof.verificationMethod, PATTERNS.didUrl, where + '.verificationMethod');
  if (!RELATIONSHIPS.includes(proof.proofPurpose)) throw new AutheoError('malformed', where + '.proofPurpose');
  if (proof['@context'] !== undefined && proof['@context'] !== null) {
    list(proof['@context'], 0, 8, (v, w) => { if (typeof v !== 'string') throw new AutheoError('malformed', w); },
      where + '.@context');
  }
  str(proof.proofValue, PATTERNS.proofValue, where + '.proofValue');
  if (purpose && proof.proofPurpose !== purpose) throw new AutheoError('malformed', where + '.proofPurpose');
}

export function checkCapability(cap, where = 'capability') {
  fields(cap, ['schema_version', 'environments', 'scopes', 'resources', 'tools', 'asset', 'per_action_minor',
    'total_budget_minor', 'approval_threshold_minor', 'max_delegation_depth'],
  ['environments', 'scopes', 'resources', 'per_action_minor', 'total_budget_minor', 'approval_threshold_minor'], where);
  if ('schema_version' in cap) literal(cap.schema_version, 'autheo.capability/v2', where + '.schema_version');
  if ('asset' in cap) str(cap.asset, PATTERNS.asset, where + '.asset');
  const grants = (v, w) => str(v, PATTERNS.grant, w);
  list(cap.environments, 1, 20, grants, where + '.environments');
  list(cap.scopes, 1, 12, (v, w) => { if (!SCOPES.includes(v)) throw new AutheoError('malformed', w); },
    where + '.scopes');
  list(cap.resources, 1, 50, grants, where + '.resources');
  const tools = cap.tools === undefined ? [] : cap.tools;
  list(tools, 0, 100, grants, where + '.tools');
  for (const name of ['environments', 'scopes', 'resources']) unique(cap[name], where + '.' + name);
  unique(tools, where + '.tools');
  for (const name of ['per_action_minor', 'total_budget_minor', 'approval_threshold_minor']) {
    if (!isInt(cap[name], 0, MINOR_MAX)) throw new AutheoError('malformed', where + '.' + name);
  }
  if ('max_delegation_depth' in cap && !isInt(cap.max_delegation_depth, 0, 8)) {
    throw new AutheoError('malformed', where + '.max_delegation_depth');
  }
  if (!(cap.approval_threshold_minor <= cap.per_action_minor && cap.per_action_minor <= cap.total_budget_minor)) {
    throw new AutheoError('malformed', where + ' limits');
  }
}

export const capabilityOf = (cap) => ({ tools: [], max_delegation_depth: 0, asset: 'DEMO', ...cap });

export function checkDelegation(doc, where = 'delegation') {
  fields(doc, ['@context', 'type', 'id', 'issuer', 'validFrom', 'validUntil', 'credentialSubject', 'proof'],
    ['@context', 'type', 'id', 'issuer', 'validFrom', 'validUntil', 'credentialSubject', 'proof'], where);
  if (!Array.isArray(doc['@context']) || doc['@context'].length !== 1 || doc['@context'][0] !== VC_CONTEXT) {
    throw new AutheoError('malformed', where + '.@context');
  }
  if (!Array.isArray(doc.type) || doc.type.length !== 2 || doc.type[0] !== 'VerifiableCredential'
      || doc.type[1] !== 'AutheoDelegation') throw new AutheoError('malformed', where + '.type');
  str(doc.id, PATTERNS.urn, where + '.id');
  str(doc.issuer, PATTERNS.did, where + '.issuer');
  str(doc.validFrom, PATTERNS.dateTime, where + '.validFrom');
  str(doc.validUntil, PATTERNS.dateTime, where + '.validUntil');
  const subject = doc.credentialSubject;
  fields(subject, ['id', 'schema_version', 'capability', 'parent'], ['id', 'capability'], where + '.credentialSubject');
  str(subject.id, PATTERNS.did, where + '.credentialSubject.id');
  if ('schema_version' in subject) literal(subject.schema_version, 'autheo.delegation/v2', where + '.schema_version');
  checkCapability(subject.capability, where + '.credentialSubject.capability');
  if (subject.parent !== undefined && subject.parent !== null) {
    fields(subject.parent, ['id', 'digest'], ['id', 'digest'], where + '.parent');
    str(subject.parent.id, PATTERNS.urn, where + '.parent.id');
    str(subject.parent.digest, PATTERNS.hex64, where + '.parent.digest');
  }
  checkProof(doc.proof, 'capabilityDelegation', where + '.proof');
}

export function checkRevocation(doc, where = 'revocation') {
  fields(doc, ['type', 'schema_version', 'id', 'issuer', 'target', 'revoked_at', 'reason', 'proof'],
    ['type', 'id', 'issuer', 'target', 'revoked_at', 'proof'], where);
  literal(doc.type, 'AutheoRevocation', where + '.type');
  if ('schema_version' in doc) literal(doc.schema_version, 'autheo.revocation/v2', where + '.schema_version');
  str(doc.id, PATTERNS.urn, where + '.id');
  str(doc.issuer, PATTERNS.did, where + '.issuer');
  fields(doc.target, ['id', 'digest'], ['id', 'digest'], where + '.target');
  str(doc.target.id, PATTERNS.urn, where + '.target.id');
  str(doc.target.digest, PATTERNS.hex64, where + '.target.digest');
  str(doc.revoked_at, PATTERNS.dateTime, where + '.revoked_at');
  if ('reason' in doc) str(doc.reason, PATTERNS.revocationReason, where + '.reason');
  checkProof(doc.proof, 'assertionMethod', where + '.proof');
}

export function checkInvocation(doc, where = 'invocation') {
  fields(doc, ['type', 'schema_version', 'id', 'invoker', 'environment', 'action', 'resource', 'tool', 'amount_minor',
    'asset', 'created', 'expires', 'capability', 'proof'],
  ['type', 'id', 'invoker', 'environment', 'action', 'resource', 'created', 'expires', 'capability', 'proof'], where);
  literal(doc.type, 'AutheoInvocation', where + '.type');
  if ('schema_version' in doc) literal(doc.schema_version, 'autheo.invocation/v2', where + '.schema_version');
  if ('asset' in doc) str(doc.asset, PATTERNS.asset, where + '.asset');
  str(doc.id, PATTERNS.identifier, where + '.id');
  str(doc.invoker, PATTERNS.did, where + '.invoker');
  str(doc.environment, PATTERNS.identifier, where + '.environment');
  if (!SCOPES.includes(doc.action)) throw new AutheoError('malformed', where + '.action');
  str(doc.resource, PATTERNS.identifier, where + '.resource');
  if (doc.tool !== undefined && doc.tool !== null) str(doc.tool, PATTERNS.tool, where + '.tool');
  if ('amount_minor' in doc && !isInt(doc.amount_minor, 0, MINOR_MAX)) throw new AutheoError('malformed', where + '.amount');
  str(doc.created, PATTERNS.dateTime, where + '.created');
  str(doc.expires, PATTERNS.dateTime, where + '.expires');
  list(doc.capability, 1, MAX_CHAIN_LENGTH, (v, w) => checkDelegation(v, w), where + '.capability');
  checkProof(doc.proof, 'capabilityInvocation', where + '.proof');
}

const RECEIPT_FIELDS = ['type', 'schema_version', 'id', 'issuer', 'environment', 'sequence', 'previous_hash',
  'recorded_at', 'kind', 'decision', 'reasons', 'document_digest', 'request_id', 'invoker', 'root', 'chain', 'action',
  'resource', 'tool', 'amount_minor', 'asset', 'policy_id', 'policy_digest', 'reference', 'executed', 'simulation_only', 'proof'];

export function checkReceipt(doc, where = 'receipt') {
  fields(doc, RECEIPT_FIELDS, ['type', 'id', 'issuer', 'environment', 'sequence', 'previous_hash', 'recorded_at', 'kind',
    'decision', 'reasons', 'document_digest', 'proof'], where);
  literal(doc.type, 'AutheoReceipt', where + '.type');
  if ('schema_version' in doc) literal(doc.schema_version, 'autheo.receipt/v2', where + '.schema_version');
  str(doc.id, PATTERNS.urn, where + '.id');
  str(doc.issuer, PATTERNS.did, where + '.issuer');
  str(doc.environment, PATTERNS.identifier, where + '.environment');
  if (!isInt(doc.sequence, 1, Number.MAX_SAFE_INTEGER)) throw new AutheoError('malformed', where + '.sequence');
  str(doc.previous_hash, PATTERNS.hex64, where + '.previous_hash');
  if (!isInt(doc.recorded_at, 0, Number.MAX_SAFE_INTEGER)) throw new AutheoError('malformed', where + '.recorded_at');
  if (!['decision', 'revocation'].includes(doc.kind)) throw new AutheoError('malformed', where + '.kind');
  if (!['allow', 'escalate', 'block', 'recorded'].includes(doc.decision)) throw new AutheoError('malformed', where);
  list(doc.reasons, 0, 64, (v, w) => str(v, PATTERNS.reason, w), where + '.reasons');
  str(doc.document_digest, PATTERNS.hex64, where + '.document_digest');
  const optional = { request_id: PATTERNS.identifier, invoker: PATTERNS.did, root: PATTERNS.did,
    resource: PATTERNS.identifier, tool: PATTERNS.tool, asset: PATTERNS.asset, policy_id: PATTERNS.identifier, policy_digest: PATTERNS.hex64,
    reference: PATTERNS.urn };
  for (const [name, pattern] of Object.entries(optional)) {
    if (doc[name] !== undefined && doc[name] !== null) str(doc[name], pattern, where + '.' + name);
  }
  if (doc.action !== undefined && doc.action !== null && !SCOPES.includes(doc.action)) {
    throw new AutheoError('malformed', where + '.action');
  }
  if ('amount_minor' in doc && !isInt(doc.amount_minor, 0, MINOR_MAX)) throw new AutheoError('malformed', where);
  if ('chain' in doc) {
    list(doc.chain, 0, MAX_CHAIN_LENGTH, (link, w) => {
      fields(link, ['id', 'digest', 'issuer', 'subject'], ['id', 'digest', 'issuer', 'subject'], w);
      str(link.id, PATTERNS.urn, w); str(link.digest, PATTERNS.hex64, w);
      str(link.issuer, PATTERNS.did, w); str(link.subject, PATTERNS.did, w);
    }, where + '.chain');
  }
  if ('executed' in doc) literal(doc.executed, false, where + '.executed');
  if ('simulation_only' in doc) literal(doc.simulation_only, true, where + '.simulation_only');
  checkProof(doc.proof, 'assertionMethod', where + '.proof');
}

export function checkBundle(doc) {
  fields(doc, ['schema_version', 'receipt', 'invocation', 'revocations'], ['receipt', 'invocation'], 'bundle');
  if ('schema_version' in doc) literal(doc.schema_version, 'autheo.bundle/v2', 'bundle.schema_version');
  checkReceipt(doc.receipt, 'bundle.receipt');
  checkInvocation(doc.invocation, 'bundle.invocation');
  list(doc.revocations === undefined ? [] : doc.revocations, 0, 1000, (v, w) => checkRevocation(v, w),
    'bundle.revocations');
}

// ------------------------------------------------------------------ Data Integrity eddsa-jcs-2022
export async function hashData(unsecured, proofConfig) {
  return concat(await sha256(jcsBytes(proofConfig)), await sha256(jcsBytes(unsecured)));
}

async function ed25519Verify(raw, signature, data) {
  const key = await subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  return subtle.verify({ name: 'Ed25519' }, key, signature, data);
}

// Verify the single proof of a secured document for the expected purpose. Throws AutheoError with
// code bad_format | bad_proof | bad_verification_method | bad_signature; returns { controller, created }.
export async function verifyProof(secured, purpose, documents = {}) {
  if (!isObject(secured)) throw new AutheoError('bad_format');
  const proof = secured.proof;
  if (!isObject(proof)) throw new AutheoError('bad_proof', 'exactly one proof object is required');
  for (const key of Object.keys(proof)) if (!PROOF_MEMBERS.has(key)) throw new AutheoError('bad_proof', key);
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') throw new AutheoError('bad_proof');
  if (proof.proofPurpose !== purpose) throw new AutheoError('bad_proof', 'purpose');
  let created;
  let signature;
  try {
    created = parseTime(proof.created);
    signature = multibaseDecode(proof.proofValue);
  } catch { throw new AutheoError('bad_proof', 'created/proofValue'); }
  if (signature.length !== 64) throw new AutheoError('bad_proof', 'signature length');
  const options = { ...proof };
  delete options.proofValue;
  const unsecured = { ...secured };
  delete unsecured.proof;
  if ('@context' in options) {
    const prefix = Array.isArray(options['@context']) ? options['@context'] : [options['@context']];
    const current = Array.isArray(secured['@context']) ? secured['@context'] : [secured['@context']];
    if (jcs(current.slice(0, prefix.length)) !== jcs(prefix)) throw new AutheoError('bad_proof', '@context');
    unsecured['@context'] = options['@context'];
  }
  let controller;
  let raw;
  try { [controller, raw] = resolveKey(proof.verificationMethod, purpose, documents); } catch (error) {
    throw new AutheoError('bad_verification_method', error.message);
  }
  let data;
  try { data = await hashData(unsecured, options); } catch (error) { throw new AutheoError('bad_format', error.message); }
  let ok = false;
  try { ok = await ed25519Verify(raw, signature, data); } catch { ok = false; }
  if (!ok) throw new AutheoError('bad_signature');
  return { controller, created };
}

const PKCS8_ED25519 = fromHex('302e020100300506032b657004220420');

// Sign with a raw 32-byte Ed25519 seed (did:key signer). Returns the secured copy of document.
export async function signDocument(document, seed, purpose, createdEpoch) {
  const key = await subtle.importKey('pkcs8', concat(PKCS8_ED25519, seed), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', key);
  const did = didKeyFromPublic(fromBase64Url(jwk.x));
  const proof = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: formatTime(createdEpoch),
    verificationMethod: did + '#' + did.split(':')[2], proofPurpose: purpose };
  if ('@context' in document) proof['@context'] = document['@context'];
  const signature = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key, await hashData(document, proof)));
  return { ...document, proof: { ...proof, proofValue: multibaseEncode(signature) } };
}

export async function didFromSeed(seed) {
  const key = await subtle.importKey('pkcs8', concat(PKCS8_ED25519, seed), { name: 'Ed25519' }, true, ['sign']);
  return didKeyFromPublic(fromBase64Url((await subtle.exportKey('jwk', key)).x));
}

// ------------------------------------------------------------------ attenuation
export function patternMatches(pattern, value) {
  if (value === null || value === undefined) return false;
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return value.startsWith(pattern.slice(0, -1));
  return value === pattern;
}

export function patternCovers(parents, child) {
  for (const parent of parents) {
    if (parent === '*') return true;
    if (parent.endsWith('*')) {
      if ((child.endsWith('*') ? child.slice(0, -1) : child).startsWith(parent.slice(0, -1))) return true;
    } else if (child === parent) return true;
  }
  return false;
}

export function attenuationProblems(parent, child) {
  const p = capabilityOf(parent);
  const c = capabilityOf(child);
  const problems = [];
  for (const name of ['environments', 'resources', 'tools']) {
    for (const pattern of c[name]) if (!patternCovers(p[name], pattern)) problems.push(name + ': ' + pattern);
  }
  for (const scope of c.scopes) if (!hasScope(p.scopes, scope)) problems.push('scopes: ' + scope);
  if (c.asset !== p.asset) problems.push('asset: ' + c.asset);
  for (const name of ['per_action_minor', 'total_budget_minor', 'approval_threshold_minor']) {
    if (c[name] > p[name]) problems.push(name);
  }
  return problems;
}

export function capabilityProblems(capability, request) {
  const cap = capabilityOf(capability);
  const tool = request.tool === undefined ? null : request.tool;
  const problems = [];
  if (!cap.environments.some((p) => patternMatches(p, request.environment))) problems.push('environment_denied');
  if (!hasScope(cap.scopes, request.action)) problems.push('scope_denied');
  if (!cap.resources.some((p) => patternMatches(p, request.resource))) problems.push('resource_denied');
  if (request.action === 'tool.invoke' && tool === null) problems.push('tool_required');
  else if (tool !== null && !cap.tools.some((p) => patternMatches(p, tool))) problems.push('tool_denied');
  if ((request.asset || 'DEMO') !== cap.asset) problems.push('asset_mismatch');
  if ((request.amount_minor || 0) > cap.per_action_minor) problems.push('per_action_limit');
  return problems;
}

// Outcome of the mandate-only policy for a verified invocation (result = verifyInvocation(...)), mirroring
// Python didenv.decide_invocation; checked by verify-venue-vectors.mjs. options: { environment (required: the
// deciding environment / venue id), history (this decider's earlier decision receipts, for budgets) }.
// Throws AutheoError wrong_environment / chain_not_authentic: reject, do not record. Declarative
// autheo.policy/v1 rules are NOT implemented here; deciders that need them use the Python service.
export function decideInvocation(result, options = {}) {
  const { invocation, chain } = result;
  if (invocation.environment !== options.environment) throw new AutheoError('wrong_environment', invocation.environment);
  if (!chain.authentic) throw new AutheoError('chain_not_authentic');
  const cap = chain.capability;
  const amount = invocation.amount_minor || 0;
  const tool = invocation.tool === undefined ? null : invocation.tool;
  const decisions = (options.history || []).filter((r) => r.kind === 'decision');
  const spentUnder = (id, leafOnly) => decisions.filter((r) => r.decision === 'allow' && Array.isArray(r.chain)
    && r.chain.length && (leafOnly ? r.chain[r.chain.length - 1].id === id : r.chain.some((l) => l.id === id)))
    .reduce((sum, r) => sum + (r.amount_minor || 0), 0);
  const blocks = [];
  const block = (reason) => { if (!blocks.includes(reason)) blocks.push(reason); };
  for (const e of chain.errors) block('delegation_' + e.code + ':' + e.index);
  if (!cap.environments.some((p) => patternMatches(p, options.environment))) block('environment_denied');
  if ((invocation.asset || 'DEMO') !== cap.asset) block('asset_mismatch');
  if (!hasScope(cap.scopes, invocation.action)) block('scope_denied');
  if (!cap.resources.some((p) => patternMatches(p, invocation.resource))) block('resource_denied');
  if (amount > cap.per_action_minor) block('per_action_limit');
  const leaf = chain.links[chain.links.length - 1];
  if (spentUnder(leaf.id, true) + amount > cap.total_budget_minor) block('total_budget_limit');
  chain.links.slice(0, -1).forEach((link, i) => {
    const limit = invocation.capability[i].credentialSubject.capability.total_budget_minor;
    if (spentUnder(link.id, false) + amount > limit) block('chain_budget_limit:' + link.index);
  });
  if (invocation.action === 'tool.invoke' && tool === null) block('tool_required');
  else if (tool !== null && !cap.tools.some((p) => patternMatches(p, tool))) block('tool_denied');
  const policy = MANDATE_ONLY_POLICY;
  if (blocks.length) return { decision: 'block', reasons: blocks, ...policy };
  if (amount > cap.approval_threshold_minor) return { decision: 'escalate', reasons: ['human_review_required'], ...policy };
  return { decision: 'allow', reasons: ['within_demo_policy'], ...policy };
}

// Sign the decision receipt for a verified invocation (autheo.receipt/v2, assertionMethod). The issuer is the
// did:key of seed; the receipt verifies with verifyReceipt/verifyBundle like an environment's own.
// at: { id (urn:uuid), sequence, previousHash, recordedAt (epoch seconds) }.
export async function signDecisionReceipt(result, decision, seed, environment, at) {
  const { invocation, chain } = result;
  const body = { type: 'AutheoReceipt', schema_version: 'autheo.receipt/v2', id: at.id, issuer: await didFromSeed(seed),
    environment, sequence: at.sequence, previous_hash: at.previousHash, recorded_at: at.recordedAt, kind: 'decision',
    decision: decision.decision, reasons: decision.reasons, document_digest: result.digest, request_id: invocation.id,
    invoker: invocation.invoker, root: chain.root,
    chain: chain.links.map((l) => ({ id: l.id, digest: l.digest, issuer: l.issuer, subject: l.subject })),
    action: invocation.action, resource: invocation.resource, amount_minor: invocation.amount_minor || 0,
    asset: invocation.asset || 'DEMO', policy_id: decision.policy_id, policy_digest: decision.policy_digest,
    executed: false, simulation_only: true };
  if (invocation.tool !== undefined && invocation.tool !== null) body.tool = invocation.tool;
  return signDocument(body, seed, 'assertionMethod', at.recordedAt);
}

// ------------------------------------------------------------------ revocations and chains
export async function verifyRevocation(record, documents = {}) {
  try { checkRevocation(record); } catch { throw new AutheoError('malformed'); }
  const { controller } = await verifyProof(record, 'assertionMethod', documents);
  if (controller !== record.issuer) throw new AutheoError('bad_signature', 'revocation proof is not by its issuer');
  return record;
}

// Verify [root, ..., leaf] at epoch "at". Never throws on bad input. options: { at, trustedRoots (array|null),
// revocations, skew, documents }.
export async function verifyChain(chain, options = {}) {
  const at = options.at;
  const skew = options.skew === undefined ? CLOCK_SKEW_SECONDS : options.skew;
  const roots = options.trustedRoots === undefined || options.trustedRoots === null ? null : new Set(options.trustedRoots);
  const documents = options.documents || {};
  const result = { at, errors: [], links: [], root: null, leaf: null, capability: null, ignoredRevocations: 0 };
  const fail = (index, code, detail = '') => result.errors.push({ index, code, detail });
  const finish = () => {
    result.authentic = !result.errors.some((e) => AUTHENTICITY_ERRORS.has(e.code));
    result.valid = result.errors.length === 0;
    return result;
  };
  if (!Array.isArray(chain) || chain.length === 0) { fail(0, 'malformed', 'chain must be a non-empty list'); return finish(); }
  if (chain.length > MAX_CHAIN_LENGTH) { fail(0, 'chain_too_long'); return finish(); }
  const parsed = [];
  for (let index = 0; index < chain.length; index += 1) {
    const raw = chain[index];
    try { checkDelegation(raw); } catch (error) { fail(index, 'malformed', error.message); parsed.push(null); continue; }
    try {
      const { controller } = await verifyProof(raw, 'capabilityDelegation', documents);
      if (controller !== raw.issuer) throw new AutheoError('bad_signature', 'proof is not by the issuer');
    } catch (error) { fail(index, 'bad_signature', error.message); parsed.push(null); continue; }
    parsed.push({ raw, digest: await digest(raw) });
  }
  const usable = {};
  for (const record of options.revocations || []) {
    try { await verifyRevocation(record, documents); } catch { result.ignoredRevocations += 1; continue; }
    (usable[record.target.id] = usable[record.target.id] || []).push(record);
  }
  const issuers = [];
  for (let index = 0; index < parsed.length; index += 1) {
    const entry = parsed[index];
    if (entry === null) { issuers.push(''); continue; }
    const { raw, digest: linkDigest } = entry;
    const subject = raw.credentialSubject;
    const capability = capabilityOf(subject.capability);
    issuers.push(raw.issuer);
    const validFrom = parseTime(raw.validFrom);
    const validUntil = parseTime(raw.validUntil);
    result.links.push({ index, id: raw.id, digest: linkDigest, issuer: raw.issuer, subject: subject.id,
      valid_from: raw.validFrom, valid_until: raw.validUntil });
    if (!(validUntil - validFrom > 0 && validUntil - validFrom <= MAX_DELEGATION_SECONDS)) fail(index, 'malformed', 'window');
    if (index === 0) {
      if (subject.parent !== undefined && subject.parent !== null) fail(index, 'broken_link', 'root names a parent');
      if (roots !== null && !roots.has(raw.issuer)) fail(index, 'untrusted_root', raw.issuer);
    } else {
      const previous = parsed[index - 1];
      if (previous === null) fail(index, 'broken_link', 'parent link could not be verified');
      else {
        const parent = previous.raw;
        const ref = subject.parent;
        if (!ref || ref.id !== parent.id || ref.digest !== previous.digest) fail(index, 'broken_link', 'parent id/digest');
        if (raw.issuer !== parent.credentialSubject.id) fail(index, 'broken_link', 'issuer is not the parent subject');
        for (const problem of attenuationProblems(parent.credentialSubject.capability, capability)) {
          fail(index, 'attenuation_violation', problem);
        }
        if (validFrom < parseTime(parent.validFrom) || validUntil > parseTime(parent.validUntil)) {
          fail(index, 'attenuation_violation', 'validity window widened');
        }
        const parentDepth = capabilityOf(parent.credentialSubject.capability).max_delegation_depth;
        if (parentDepth < 1) fail(index, 'depth_exceeded', 'parent does not allow sub-delegation');
        else if (capability.max_delegation_depth > parentDepth - 1) fail(index, 'depth_exceeded', 'depth not reduced');
      }
    }
    if (validFrom > at + skew) fail(index, 'not_yet_valid', raw.validFrom);
    if (at >= validUntil) fail(index, 'expired', raw.validUntil);
    const entitled = new Set([...issuers.filter(Boolean), subject.id]);
    for (const record of usable[raw.id] || []) {
      if (record.target.digest === linkDigest && entitled.has(record.issuer) && parseTime(record.revoked_at) <= at) {
        fail(index, 'revoked', record.id);
        break;
      }
    }
  }
  if (parsed[0] !== null) result.root = parsed[0].raw.issuer;
  const last = parsed[parsed.length - 1];
  if (last !== null) {
    result.leaf = last.raw.credentialSubject.id;
    result.capability = capabilityOf(last.raw.credentialSubject.capability);
  }
  return finish();
}

// Verify an invocation's own proof/lifetime (throws AutheoError) and its chain (returned).
export async function verifyInvocation(invocation, options = {}) {
  try { checkInvocation(invocation); } catch (error) { throw new AutheoError('malformed', error.message); }
  const { controller } = await verifyProof(invocation, 'capabilityInvocation', options.documents || {});
  if (controller !== invocation.invoker) throw new AutheoError('bad_signature', 'invocation proof is not by the invoker');
  const skew = options.skew === undefined ? CLOCK_SKEW_SECONDS : options.skew;
  const created = parseTime(invocation.created);
  const expires = parseTime(invocation.expires);
  if (!(expires - created > 0 && expires - created <= MAX_INVOCATION_SECONDS)) throw new AutheoError('malformed', 'lifetime');
  if (options.at >= expires) throw new AutheoError('expired');
  if (created > options.at + skew) throw new AutheoError('not_yet_valid');
  const chain = await verifyChain(invocation.capability, options);
  if (chain.leaf !== null && chain.leaf !== invocation.invoker) {
    chain.errors.push({ index: invocation.capability.length - 1, code: 'invoker_mismatch', detail: '' });
    chain.authentic = false;
    chain.valid = false;
  }
  return { invocation, chain, digest: await digest(invocation), created, expires };
}

export async function verifyReceipt(receipt, issuer = null, documents = {}) {
  try { checkReceipt(receipt); } catch { throw new AutheoError('malformed'); }
  const { controller } = await verifyProof(receipt, 'assertionMethod', documents);
  if (controller !== receipt.issuer) throw new AutheoError('bad_signature', 'receipt proof is not by its issuer');
  if (issuer !== null && receipt.issuer !== issuer) throw new AutheoError('untrusted_issuer');
  return receipt;
}

export async function chainHash(previousHash, receipt) {
  if (!PATTERNS.hex64.test(previousHash)) throw new AutheoError('bad_hash');
  return hex(await sha256(concat(encoder.encode(previousHash), jcsBytes(receipt))));
}

// Verify an ordered v2 receipt chain (ledger export). options: { issuer, environment, expectedHead, documents }.
export async function verifyReceipts(receipts, options = {}) {
  const problems = [];
  const problem = (sequence, reason) => { if (problems.length < 50) problems.push({ sequence, problem: reason }); };
  let previous = ZERO_HASH;
  const ids = new Set();
  const list_ = Array.isArray(receipts) ? receipts : [];
  for (let i = 0; i < list_.length; i += 1) {
    const index = i + 1;
    const receipt = list_[i];
    try { await verifyReceipt(receipt, options.issuer === undefined ? null : options.issuer, options.documents); } catch (error) {
      problem(index, 'receipt_invalid:' + error.code);
      try { previous = await chainHash(previous, receipt); } catch { /* unhashable */ }
      continue;
    }
    if (receipt.sequence !== index) problem(index, 'sequence_gap_or_reorder');
    if (receipt.previous_hash !== previous) problem(index, 'previous_hash_mismatch');
    if (options.environment !== undefined && options.environment !== null && receipt.environment !== options.environment) {
      problem(index, 'wrong_environment');
    }
    if (ids.has(receipt.id)) problem(index, 'duplicate_receipt_id');
    ids.add(receipt.id);
    previous = await chainHash(previous, receipt);
  }
  const anchorMatches = options.expectedHead === undefined || options.expectedHead === null ? null
    : previous === options.expectedHead;
  if (anchorMatches === false) problem(list_.length, 'head_differs_from_anchor');
  return { valid: problems.length === 0, count: list_.length, head: previous,
    firstInvalidSequence: problems.length ? problems[0].sequence : null, problems, anchorMatches };
}

// Verify a decision bundle back to a root DID as of the receipt's recorded_at. options: { trustedRoots (array|null),
// environmentDid, revocations (extra), skew, documents }.
export async function verifyBundle(bundle, options = {}) {
  const report = { valid: false, problems: [], networkUsed: false,
    rootPinned: options.trustedRoots !== undefined && options.trustedRoots !== null };
  const problems = report.problems;
  try { checkBundle(bundle); } catch (error) { problems.push('malformed_bundle: ' + error.message); return report; }
  const receipt = bundle.receipt;
  const invocation = bundle.invocation;
  try { await verifyReceipt(receipt, options.environmentDid || null, options.documents); } catch (error) {
    problems.push('receipt_invalid:' + error.code); return report;
  }
  Object.assign(report, { decision: receipt.decision, reasons: receipt.reasons, environment: receipt.environment,
    issuer: receipt.issuer, recordedAt: receipt.recorded_at });
  if (receipt.kind !== 'decision') { problems.push('receipt_is_not_a_decision'); return report; }
  if (await digest(invocation) !== receipt.document_digest) { problems.push('invocation_digest_mismatch'); return report; }
  let result;
  try {
    result = await verifyInvocation(invocation, { ...options, at: receipt.recorded_at,
      revocations: [...(bundle.revocations || []), ...(options.revocations || [])] });
  } catch (error) { problems.push('invocation_invalid:' + error.code); return report; }
  const chain = result.chain;
  Object.assign(report, { invoker: invocation.invoker, root: chain.root, requestId: invocation.id, chain });
  const value = (v) => (v === undefined ? null : v);
  const bindings = {
    request_id: [receipt.request_id, invocation.id], invoker: [receipt.invoker, invocation.invoker],
    environment: [receipt.environment, invocation.environment], action: [receipt.action, invocation.action],
    resource: [receipt.resource, invocation.resource], tool: [value(receipt.tool), value(invocation.tool)],
    amount_minor: [value(receipt.amount_minor) ?? 0, value(invocation.amount_minor) ?? 0],
    asset: [receipt.asset || 'DEMO', invocation.asset || 'DEMO'],
    root: [receipt.root, chain.root],
    chain: [jcs(receipt.chain || []), jcs(chain.links.map((l) => ({ id: l.id, digest: l.digest, issuer: l.issuer,
      subject: l.subject })))],
  };
  for (const [name, [recorded, actual]] of Object.entries(bindings)) {
    if (value(recorded) !== value(actual)) problems.push('receipt_binding_mismatch:' + name);
  }
  if (!chain.authentic) problems.push('delegation_chain_not_authentic');
  const requestProblems = chain.capability ? capabilityProblems(chain.capability, invocation) : [];
  const authorized = chain.valid && requestProblems.length === 0;
  report.authorizedByChain = authorized;
  report.requestProblems = requestProblems;
  if (receipt.decision === 'allow' && !authorized) problems.push('allow_not_supported_by_chain');
  report.valid = problems.length === 0;
  report.verdict = report.valid ? receipt.decision + '_verified' : 'invalid';
  return report;
}

export const decodeUtf8 = (bytes) => decoder.decode(bytes);
