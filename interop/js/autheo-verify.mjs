// Reference JavaScript verifier for Autheo signed documents (Node >= 20, no dependencies).
// Normative rules: docs/SPEC-SIGNATURES.md. Suitable as a starting point for the JARVIS kernel.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export const MAX_TTL = Object.freeze({
  passport: 86400, mandate: 3600, request: 300, handoff: 300,
  'trust-snapshot': 300, receipt: 86400, outcome: 300,
});
export const ZERO_HASH = '0'.repeat(64);
const REQUIRED = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti', 'body'];

// autheo-cjson/1: sorted keys, no whitespace, every char outside 0x20-0x7E escaped (lowercase \uXXXX
// unless JSON.stringify already used a short escape), safe integers only.
export function canonicalize(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON allows safe integers only');
    return String(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value).replace(/[\u007f-\uffff]/g,
      (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (typeof value === 'object') {
    // Keys are compared by UTF-16 code unit here; identical to code-point order for the
    // ASCII keys Autheo uses. Non-BMP keys are outside the v1 profile.
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => canonicalize(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  throw new Error('value is not representable in canonical JSON');
}

export function sha256Hex(text) {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

export const digest = (value) => sha256Hex(canonicalize(value));

export function chainHash(previousHash, token) {
  if (!/^[0-9a-f]{64}$/.test(previousHash)) throw new Error('previous hash must be 64 lowercase hex');
  return sha256Hex(previousHash + token);
}

function decodeSegment(segment) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('segment is not base64url');
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

// Returns {ok:true, header, claims} or {ok:false, error} where error is one of
// bad_format | bad_header | bad_signature | bad_claims | expired | not_yet_valid.
export function verifyJws(token, { kind, issuer, audience, jwk, kid, now, historical = false, skew = 2 }) {
  if (typeof token !== 'string' || token.length > 131072) return { ok: false, error: 'bad_format' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, error: 'bad_format' };
  let header;
  try { header = decodeSegment(parts[0]); } catch { return { ok: false, error: 'bad_format' }; }
  if (header.alg !== 'EdDSA' || header.typ !== `autheo-${kind}+jwt` || header.kid !== (kid ?? jwk.kid) || header.crit) {
    return { ok: false, error: 'bad_header' };
  }
  if (historical && kind !== 'receipt') return { ok: false, error: 'bad_claims' };
  const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' });
  const signed = Buffer.from(parts[0] + '.' + parts[1], 'ascii');
  let valid = false;
  try { valid = cryptoVerify(null, signed, key, Buffer.from(parts[2], 'base64url')); } catch { valid = false; }
  if (!valid) return { ok: false, error: 'bad_signature' };
  let claims;
  try { claims = decodeSegment(parts[1]); } catch { return { ok: false, error: 'bad_format' }; }
  if (REQUIRED.some((k) => !(k in claims))) return { ok: false, error: 'bad_claims' };
  if (!['iat', 'nbf', 'exp'].every((k) => Number.isSafeInteger(claims[k]))) return { ok: false, error: 'bad_claims' };
  if (claims.iss !== issuer || claims.aud !== audience) return { ok: false, error: 'bad_claims' };
  if (typeof claims.jti !== 'string' || !claims.jti || typeof claims.body !== 'object' || claims.body === null
      || Array.isArray(claims.body)) return { ok: false, error: 'bad_claims' };
  if (!historical && claims.exp <= now) return { ok: false, error: 'expired' };
  if (claims.iat > now + skew || claims.nbf > now + skew) return { ok: false, error: 'not_yet_valid' };
  const lifetime = claims.exp - claims.iat;
  if (claims.nbf !== claims.iat || lifetime <= 0 || lifetime > MAX_TTL[kind]) return { ok: false, error: 'bad_claims' };
  return { ok: true, header, claims };
}

// Verify an ordered receipt chain [{sequence, token, chain_hash}]; returns {valid, head, firstInvalidSequence}.
export function verifyChain(receipts, { issuer, audience, jwk, kid, now = Math.floor(Date.now() / 1000) }) {
  let previous = ZERO_HASH;
  for (const [index, entry] of receipts.entries()) {
    const sequence = index + 1;
    const result = verifyJws(entry.token, { kind: 'receipt', issuer, audience, jwk, kid, now, historical: true });
    const recomputed = chainHash(previous, entry.token);
    const body = result.ok ? result.claims.body : {};
    if (!result.ok || entry.sequence !== sequence || recomputed !== entry.chain_hash
        || body.sequence !== sequence || body.previous_hash !== previous || body.executed !== false) {
      return { valid: false, head: null, firstInvalidSequence: sequence };
    }
    previous = recomputed;
  }
  return { valid: true, head: previous, firstInvalidSequence: null };
}
