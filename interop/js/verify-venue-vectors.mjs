#!/usr/bin/env node
// Check tests/vectors/autheo-v2-venue-vectors.json (agents invoking a trading venue with dex.* scopes).
// Imports the verifier through its package name, so it also proves the @autheo/did package entry works.
// Usage: node interop/js/verify-venue-vectors.mjs [path]   (exit code 0 = every case agrees with Python)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as did from '@autheo/did';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.argv[2] ?? join(here, '..', '..', 'tests', 'vectors', 'autheo-v2-venue-vectors.json');
const vectors = JSON.parse(readFileSync(path, 'utf8'));
const failures = [];
let checks = 0;
const expect = (name, condition) => { checks += 1; if (!condition) failures.push(name); };
const same = (a, b) => did.jcs(a) === did.jcs(b);

// Every name the TypeScript declarations promise must exist at runtime.
const declared = [...readFileSync(join(here, 'autheo-did.d.mts'), 'utf8').matchAll(/^export (?:declare )?(?:const|function|class) (\w+)/gm)];
expect('types:declared', declared.length > 20);
for (const [, name] of declared) expect('types:' + name, name in did);
expect('policy:digest', same(did.MANDATE_ONLY_POLICY, vectors.policy));

for (const item of vectors.decision_cases) {
  let error = null;
  let decision = null;
  let result = null;
  try {
    result = await did.verifyInvocation(item.invocation, { at: item.at, trustedRoots: item.trusted_roots,
      revocations: item.revocations });
    decision = did.decideInvocation(result, { environment: vectors.venue, history: item.history });
  } catch (e) { error = e.code; }
  expect('decision:' + item.name + ':error', error === item.expect_error);
  if (decision) {
    expect('decision:' + item.name + ':outcome', decision.decision === item.expect_decision);
    expect('decision:' + item.name + ':reasons', same(decision.reasons, item.expect_reasons));
    expect('decision:' + item.name + ':digest', result.digest === item.expect_digest);
  }
}

// A venue signing its receipts with this library produces the Python reference receipts byte for byte.
const seed = did.fromHex(vectors.keys.venue.TEST_ONLY_seed_hex);
const ledger = vectors.ledger;
for (const receipt of ledger.receipts) {
  const item = vectors.decision_cases.find((c) => c.invocation.id === receipt.request_id);
  const result = await did.verifyInvocation(item.invocation, { at: item.at, trustedRoots: item.trusted_roots });
  const decision = did.decideInvocation(result, { environment: vectors.venue, history: [] });
  const signed = await did.signDecisionReceipt(result, decision, seed, vectors.venue, { id: receipt.id,
    sequence: receipt.sequence, previousHash: receipt.previous_hash, recordedAt: receipt.recorded_at });
  expect('receipt:' + receipt.sequence + ':identical', same(signed, receipt));
}
const report = await did.verifyReceipts(ledger.receipts, { issuer: ledger.issuer, environment: ledger.environment,
  expectedHead: ledger.head });
expect('ledger:valid', report.valid && report.head === ledger.head);

for (const item of vectors.bundle_cases) {
  const result = await did.verifyBundle(item.bundle, { trustedRoots: item.trusted_roots,
    environmentDid: item.environment_did });
  expect('bundle:' + item.name + ':valid', result.valid === item.expect_valid);
  expect('bundle:' + item.name + ':verdict', (result.verdict ?? null) === item.expect_verdict);
  expect('bundle:' + item.name + ':problems', same(result.problems, item.expect_problems));
}

// Deprecated alias (0.7 only): dex.order.sign and dex.order.request_signature grant and request each other.
const aliasCap = (scope) => ({ environments: ['venue:*'], scopes: [scope], resources: ['chain:*'], per_action_minor: 1,
  total_budget_minor: 1, approval_threshold_minor: 1 });
for (const [granted, asked] of [['dex.order.sign', 'dex.order.request_signature'], ['dex.order.request_signature', 'dex.order.sign']]) {
  expect('alias:' + granted + '->' + asked, did.capabilityProblems(aliasCap(granted), { environment: 'venue:x', action: asked,
    resource: 'chain:1:asset:A' }).length === 0 && did.attenuationProblems(aliasCap(granted), aliasCap(asked)).length === 0);
}
expect('alias:build-does-not-grant-sign', same(did.capabilityProblems(aliasCap('dex.order.build'),
  { environment: 'venue:x', action: 'dex.order.sign', resource: 'chain:1:asset:A' }), ['scope_denied']));

if (failures.length) {
  console.error('FAIL ' + failures.length + '/' + checks + ': ' + failures.join(', '));
  process.exit(1);
}
console.log('OK ' + checks + ' JavaScript checks agree with ' + vectors.version);
