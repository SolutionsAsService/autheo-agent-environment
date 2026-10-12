#!/usr/bin/env node
// Sign an invocation in JavaScript with a vector test seed and print it as JSON (cross-language check:
// tests/test_vectors_v2.py verifies it in Python and compares it byte-for-byte with the Python signer).
// Usage: node interop/js/sign-v2-invocation.mjs [vectors path]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { formatTime, fromHex, signDocument, didFromSeed } from './autheo-did.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.argv[2] ?? join(here, '..', '..', 'tests', 'vectors', 'autheo-v2-vectors.json');
const vectors = JSON.parse(readFileSync(path, 'utf8'));
const seed = fromHex(vectors.keys.subagent.TEST_ONLY_seed_hex);
const created = vectors.now + 10;
const invocation = {
  type: 'AutheoInvocation', schema_version: 'autheo.invocation/v2', id: 'req:v2-js', invoker: await didFromSeed(seed),
  environment: 'env:research', action: 'compute.simulate', resource: 'listing:demo-01', amount_minor: 7, asset: 'DEMO',
  created: formatTime(created), expires: formatTime(created + 60),
  capability: [vectors.delegations.root_to_agent, vectors.delegations.agent_to_subagent],
};
console.log(JSON.stringify(await signDocument(invocation, seed, 'capabilityInvocation', created)));
