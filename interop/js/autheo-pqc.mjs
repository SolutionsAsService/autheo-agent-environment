// Hybrid Ed25519 + ML-DSA-44 (mldsa44-jcs-2024) Data Integrity verification for Node >= 24
// (node:crypto ML-DSA). Browsers do not expose ML-DSA in WebCrypto yet, so this module is
// Node-only; the in-browser demo keeps verifying the classical v2 proofs.
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import * as did from './autheo-did.mjs';

export const PQ_SUITE = 'mldsa44-jcs-2024';
// Tunable strength: multicodec -> parameter set (mirrors pqc.MLDSA).
export const MLDSA = {
  0x1210: { level: 44, category: 2, pub: 1312, sig: 2420, suite: 'mldsa44-jcs-2024', oid: 0x11 },
  0x1211: { level: 65, category: 3, pub: 1952, sig: 3309, suite: 'mldsa65-jcs-2024', oid: 0x12 },
  0x1212: { level: 87, category: 5, pub: 2592, sig: 4627, suite: 'mldsa87-jcs-2024', oid: 0x13 },
};
export const PQ_SUITES = Object.values(MLDSA).map((p) => p.suite);
const derLen = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const der = (tag, body) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
// SubjectPublicKeyInfo for ML-DSA (OID 2.16.840.1.101.3.4.3.{17,18,19}, no parameters).
const mldsaSpki = (oidLast, raw) => der(0x30, Buffer.concat([
  der(0x30, Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, oidLast])),
  der(0x03, Buffer.concat([Buffer.from([0]), raw])),
]));
export const EDDSA_SUITE = 'eddsa-jcs-2022';
const ED25519_PUB = 0xed;
// SubjectPublicKeyInfo prefix for Ed25519.
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const enc = (value) => Buffer.from(did.jcs(value), 'utf8');

function decodeDidKey(didKey) {
  const fingerprint = didKey.split(':')[2];
  const bytes = did.b58decode(fingerprint.slice(1));
  const [code, used] = did.varintDecode(bytes);
  return { code, raw: Buffer.from(bytes.slice(used)), fingerprint };
}

function verifyOne(unsecured, proof, purpose) {
  if (!proof || proof.type !== 'DataIntegrityProof' || ![EDDSA_SUITE, ...PQ_SUITES].includes(proof.cryptosuite)) throw new Error('bad_proof');
  if (proof.proofPurpose !== purpose) throw new Error('bad_proof: purpose');
  const { proofValue, ...options } = proof;
  if (options['@context'] !== undefined && did.jcs(options['@context']) !== did.jcs(unsecured['@context'])) throw new Error('bad_proof: context');
  const data = Buffer.concat([sha256(enc(options)), sha256(enc(unsecured))]);
  const signature = Buffer.from(did.b58decode(proofValue.slice(1)));
  const controller = proof.verificationMethod.split('#')[0];
  const { code, raw, fingerprint } = decodeDidKey(controller);
  if (PQ_SUITES.includes(proof.cryptosuite)) {
    const p = MLDSA[code];
    if (!p || p.suite !== proof.cryptosuite || raw.length !== p.pub || proof.verificationMethod !== controller + '#' + fingerprint.slice(0, 48)) throw new Error('bad_verification_method');
    if (signature.length !== p.sig) throw new Error('bad_proof');
    const key = createPublicKey({ key: mldsaSpki(p.oid, raw), format: 'der', type: 'spki' });
    if (!nodeVerify(null, data, key, signature)) throw new Error('bad_signature');
    return { cryptosuite: proof.cryptosuite, controller, category: p.category };
  } else {
    if (code !== ED25519_PUB || raw.length !== 32 || proof.verificationMethod !== controller + '#' + fingerprint) throw new Error('bad_verification_method');
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, raw]), format: 'der', type: 'spki' });
    if (!nodeVerify(null, data, key, signature)) throw new Error('bad_signature');
  }
  return { cryptosuite: proof.cryptosuite, controller, category: 1 };
}

/** Verify a proof or proof set under policy 'classical' | 'hybrid' | 'pq' (mirrors pqc.verify_proofs). */
export function verifyProofs(secured, purpose, { policy = 'hybrid', bindings = {}, minCategory = 2 } = {}) {
  const proofs = Array.isArray(secured.proof) ? secured.proof : [secured.proof];
  if (!proofs.length || proofs.length > 2) throw new Error('bad_proof');
  const { proof, ...unsecured } = secured;
  const results = proofs.map((p) => verifyOne(unsecured, p, purpose));
  if (new Set(results.map((r) => r.cryptosuite)).size !== results.length || results.filter((r) => PQ_SUITES.includes(r.cryptosuite)).length > 1) throw new Error('bad_proof: duplicate suite');
  const classical = results.find((r) => r.cryptosuite === EDDSA_SUITE);
  const pq = results.find((r) => PQ_SUITES.includes(r.cryptosuite));
  if (pq && pq.category < minCategory) throw new Error('pq_level_too_low');
  if (policy === 'pq' && !pq) throw new Error('pq_required');
  if (policy === 'hybrid') {
    if (!classical || !pq) throw new Error('hybrid_required');
    if (bindings[classical.controller] !== pq.controller) throw new Error('unbound_keys');
  }
  return { policy, classical, pq };
}
