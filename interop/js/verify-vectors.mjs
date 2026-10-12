#!/usr/bin/env node
// Check tests/vectors/autheo-v1-vectors.json with the dependency-free JS verifier.
// Usage: node interop/js/verify-vectors.mjs [path]   (exit code 0 = all vectors agree)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { canonicalize, digest, verifyChain, verifyJws } from './autheo-verify.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.argv[2] ?? join(here, '..', '..', 'tests', 'vectors', 'autheo-v1-vectors.json');
const vectors = JSON.parse(readFileSync(path, 'utf8'));
const failures = [];
let checks = 0;
const expect = (name, condition) => { checks += 1; if (!condition) failures.push(name); };

for (const item of vectors.canonical) {
  if (item.error) {
    let threw = false;
    try { canonicalize(JSON.parse(item.json)); } catch { threw = true; }
    expect(`canonical:${item.name}:rejects`, threw);
  } else {
    expect(`canonical:${item.name}:bytes`, canonicalize(item.value) === item.canonical);
    expect(`canonical:${item.name}:sha256`, digest(item.value) === item.sha256);
  }
}

for (const doc of vectors.documents) {
  const key = vectors.keys[doc.key];
  const result = verifyJws(doc.token, {
    kind: doc.kind, issuer: doc.issuer, audience: doc.audience, jwk: key.jwk, kid: key.kid,
    now: doc.verify_at, historical: doc.historical, skew: vectors.clock_skew_seconds,
  });
  expect(`document:${doc.name}:valid=${doc.expect_valid}`, result.ok === doc.expect_valid);
  if (!doc.expect_valid) expect(`document:${doc.name}:error=${doc.expect_error}`, result.error === doc.expect_error);
}

const issuerKey = vectors.keys[vectors.chain.issuer];
const options = { issuer: vectors.chain.issuer, audience: vectors.chain.environment, jwk: issuerKey.jwk, kid: issuerKey.kid };
const chain = verifyChain(vectors.chain.receipts, options);
expect('chain:valid', chain.valid && chain.head === vectors.chain.head);
const tampered = verifyChain(vectors.tampered_chain.receipts, options);
expect('chain:tampered-detected', !tampered.valid
  && tampered.firstInvalidSequence === vectors.tampered_chain.first_invalid_sequence);
expect('digest:passport', digest(vectors.documents.find((d) => d.name === 'passport').token)
  === vectors.digests.passport_digest);
expect('digest:default_policy', digest(vectors.digests.default_policy) === vectors.digests.default_policy_digest);

if (failures.length) {
  console.error(`FAIL ${failures.length}/${checks}: ${failures.join(', ')}`);
  process.exit(1);
}
console.log(`OK ${checks} JavaScript checks agree with ${vectors.version}`);
