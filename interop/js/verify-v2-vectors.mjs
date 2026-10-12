#!/usr/bin/env node
// Check tests/vectors/autheo-v2-vectors.json with the dependency-free JS implementation (autheo-did.mjs).
// Usage: node interop/js/verify-v2-vectors.mjs [path]   (exit code 0 = every case agrees with Python)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as did from './autheo-did.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.argv[2] ?? join(here, '..', '..', 'tests', 'vectors', 'autheo-v2-vectors.json');
const vectors = JSON.parse(readFileSync(path, 'utf8'));
const failures = [];
let checks = 0;
const expect = (name, condition) => { checks += 1; if (!condition) failures.push(name); };
const same = (a, b) => did.jcs(a) === did.jcs(b); // key-order independent
const pairs = (errors) => {
  const out = [];
  for (const e of errors) if (!out.some(([i, c]) => i === e.index && c === e.code)) out.push([e.index, e.code]);
  return out.map((p) => JSON.stringify(p)).sort();
};
const prim = vectors.primitives;

for (const item of prim.base58) {
  expect('base58:' + item.encoded, did.b58encode(did.fromHex(item.hex)) === item.encoded
    && did.hex(did.b58decode(item.encoded)) === item.hex);
}
for (const item of prim.varint) {
  expect('varint:' + item.value, did.hex(did.varintEncode(item.value)) === item.hex
    && did.varintDecode(did.fromHex(item.hex))[0] === item.value);
}
for (const item of prim.jcs) {
  if (item.error) {
    let threw = false;
    try { did.jcs(JSON.parse(item.json)); } catch { threw = true; }
    expect('jcs:' + item.name + ':rejects', threw);
  } else {
    const value = JSON.parse(item.json);
    expect('jcs:' + item.name, did.jcs(value) === item.canonical && (await did.digest(value)) === item.sha256);
  }
}
for (const item of prim.did_key) {
  expect('did_key:' + item.name + ':decode', did.hex(did.publicFromDidKey(item.did)) === item.public_hex);
  expect('did_key:' + item.name + ':encode', did.didKeyFromPublic(did.fromHex(item.public_hex)) === item.did);
  if (item.seed_hex) expect('did_key:' + item.name + ':seed', (await did.didFromSeed(did.fromHex(item.seed_hex))) === item.did);
  if (item.document) expect('did_key:' + item.name + ':document', same(did.didKeyDocument(item.did), item.document));
}
for (const bad of prim.invalid_did_key) {
  let threw = false;
  try { did.publicFromDidKey(bad); } catch { threw = true; }
  expect('did_key:rejects:' + bad, threw);
}
for (const item of prim.did_web) expect('did_web:' + item.did, did.didWebUrl(item.did) === item.url);

const w3c = prim.w3c_eddsa_jcs_2022;
expect('w3c:canonical_document', did.jcs(w3c.document) === w3c.canonical_document);
expect('w3c:canonical_proof_options', did.jcs(w3c.proof_options) === w3c.canonical_proof_options);
expect('w3c:hash_data', did.hex(await did.hashData(w3c.document, w3c.proof_options)) === w3c.hash_data_hex);
const w3cSeed = did.multibaseDecode(w3c.secret_multibase).slice(2);
const w3cSigned = await did.signDocument(w3c.document, w3cSeed, 'assertionMethod', did.parseTime('2023-02-24T23:36:38Z'));
expect('w3c:proof_value', w3cSigned.proof.proofValue === w3c.proof_value && same(w3cSigned, w3c.signed));
expect('w3c:verifies', (await did.verifyProof(w3c.signed, 'assertionMethod')).controller.startsWith('did:key:z6Mk'));

for (const item of vectors.chain_cases) {
  const result = await did.verifyChain(item.chain, { at: item.at, trustedRoots: item.trusted_roots,
    revocations: item.revocations, skew: vectors.clock_skew_seconds });
  expect('chain:' + item.name + ':valid', result.valid === item.expect_valid);
  expect('chain:' + item.name + ':authentic', result.authentic === item.expect_authentic);
  expect('chain:' + item.name + ':errors', same(pairs(result.errors), item.expect_errors.map((p) => JSON.stringify(p)).sort()));
  expect('chain:' + item.name + ':root_leaf', result.root === item.expect_root && result.leaf === item.expect_leaf);
}

const root = vectors.keys.root.did;
for (const item of vectors.invocation_cases) {
  let error = null;
  let result = null;
  try { result = await did.verifyInvocation(item.invocation, { at: item.at, trustedRoots: [root] }); } catch (e) { error = e.code; }
  expect('invocation:' + item.name + ':error', error === item.expect_error);
  if (result) {
    expect('invocation:' + item.name + ':digest', result.digest === item.expect_digest);
    expect('invocation:' + item.name + ':chain', result.chain.valid === item.expect_chain_valid
      && same(pairs(result.chain.errors), item.expect_chain_errors.map((p) => JSON.stringify(p)).sort()));
  }
}

for (const item of vectors.bundle_cases) {
  const report = await did.verifyBundle(item.bundle, { trustedRoots: item.trusted_roots,
    environmentDid: item.environment_did, revocations: item.revocations });
  expect('bundle:' + item.name + ':valid', report.valid === item.expect_valid);
  expect('bundle:' + item.name + ':problems', same(report.problems, item.expect_problems));
  expect('bundle:' + item.name + ':verdict', (report.verdict ?? null) === item.expect_verdict);
  expect('bundle:' + item.name + ':authorized', (report.authorizedByChain ?? null) === item.expect_authorized);
}

const ledger = vectors.ledger;
const ledgerReport = await did.verifyReceipts(ledger.receipts, { issuer: ledger.issuer, environment: ledger.environment,
  expectedHead: ledger.head });
expect('ledger:valid', ledgerReport.valid && ledgerReport.head === ledger.head);
const tampered = await did.verifyReceipts(vectors.tampered_ledger.export.receipts, { issuer: ledger.issuer });
expect('ledger:tampered', !tampered.valid
  && tampered.firstInvalidSequence === vectors.tampered_ledger.expect_first_invalid_sequence);
const foreign = await did.verifyReceipts(ledger.receipts, { issuer: root });
expect('ledger:foreign_issuer', !foreign.valid);
expect('digest:root_to_agent', (await did.digest(vectors.delegations.root_to_agent)) === vectors.digests.root_to_agent);

if (failures.length) {
  console.error('FAIL ' + failures.length + '/' + checks + ': ' + failures.join(', '));
  process.exit(1);
}
console.log('OK ' + checks + ' JavaScript checks agree with ' + vectors.version);
