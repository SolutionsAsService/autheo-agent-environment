#!/usr/bin/env node
// Check tests/vectors/autheo-v3-pq-vectors.json with node:crypto ML-DSA (Node >= 24).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyProofs } from './autheo-pqc.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.argv[2] ?? join(here, '..', '..', 'tests', 'vectors', 'autheo-v3-pq-vectors.json');
const vectors = JSON.parse(readFileSync(path, 'utf8'));
const failures = [];
for (const c of vectors.cases) {
  let ok = true;
  try { verifyProofs(c.document, 'assertionMethod', { policy: c.policy, bindings: c.bindings }); } catch { ok = false; }
  if (ok !== c.valid) failures.push(c.name);
}
if (failures.length) { console.error('PQ vector mismatches:', failures.join(', ')); process.exit(1); }
console.log(`autheo v3 PQ vectors: ${vectors.cases.length} cases agree`);
