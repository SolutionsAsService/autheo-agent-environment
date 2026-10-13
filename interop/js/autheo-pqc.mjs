// Hybrid Ed25519 + ML-DSA-44 (mldsa44-jcs-2024) Data Integrity verification for Node >= 24
// (node:crypto ML-DSA). Browsers do not expose ML-DSA in WebCrypto yet, so this module is
// Node-only; the in-browser demo keeps verifying the classical v2 proofs.
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import * as did from './autheo-did.mjs';

export const PQ_SUITE = 'mldsa44-jcs-2024';
export const EDDSA_SUITE = 'eddsa-jcs-2022';
const MLDSA44_PUB = 0x1210;
const ED25519_PUB = 0xed;
// SubjectPublicKeyInfo prefix for ML-DSA-44 (OID 2.16.840.1.101.3.4.3.17) and Ed25519.
const MLDSA44_SPKI = Buffer.from('30820532300b06096086480165030403110382052100', 'hex');
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
  if (!proof || proof.type !== 'DataIntegrityProof' || ![EDDSA_SUITE, PQ_SUITE].includes(proof.cryptosuite)) throw new Error('bad_proof');
  if (proof.proofPurpose !== purpose) throw new Error('bad_proof: purpose');
  const { proofValue, ...options } = proof;
  if (options['@context'] !== undefined && did.jcs(options['@context']) !== did.jcs(unsecured['@context'])) throw new Error('bad_proof: context');
  const data = Buffer.concat([sha256(enc(options)), sha256(enc(unsecured))]);
  const signature = Buffer.from(did.b58decode(proofValue.slice(1)));
  const controller = proof.verificationMethod.split('#')[0];
  const { code, raw, fingerprint } = decodeDidKey(controller);
  if (proof.cryptosuite === PQ_SUITE) {
    if (code !== MLDSA44_PUB || raw.length !== 1312 || proof.verificationMethod !== controller + '#' + fingerprint.slice(0, 48)) throw new Error('bad_verification_method');
    const key = createPublicKey({ key: Buffer.concat([MLDSA44_SPKI, raw]), format: 'der', type: 'spki' });
    if (!nodeVerify(null, data, key, signature)) throw new Error('bad_signature');
  } else {
    if (code !== ED25519_PUB || raw.length !== 32 || proof.verificationMethod !== controller + '#' + fingerprint) throw new Error('bad_verification_method');
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, raw]), format: 'der', type: 'spki' });
    if (!nodeVerify(null, data, key, signature)) throw new Error('bad_signature');
  }
  return { cryptosuite: proof.cryptosuite, controller };
}

/** Verify a proof or proof set under policy 'classical' | 'hybrid' | 'pq' (mirrors pqc.verify_proofs). */
export function verifyProofs(secured, purpose, { policy = 'hybrid', bindings = {} } = {}) {
  const proofs = Array.isArray(secured.proof) ? secured.proof : [secured.proof];
  if (!proofs.length || proofs.length > 2) throw new Error('bad_proof');
  const { proof, ...unsecured } = secured;
  const results = proofs.map((p) => verifyOne(unsecured, p, purpose));
  if (new Set(results.map((r) => r.cryptosuite)).size !== results.length) throw new Error('bad_proof: duplicate suite');
  const classical = results.find((r) => r.cryptosuite === EDDSA_SUITE);
  const pq = results.find((r) => r.cryptosuite === PQ_SUITE);
  if (policy === 'pq' && !pq) throw new Error('pq_required');
  if (policy === 'hybrid') {
    if (!classical || !pq) throw new Error('hybrid_required');
    if (bindings[classical.controller] !== pq.controller) throw new Error('unbound_keys');
  }
  return { policy, classical, pq };
}
