# Autheo v2: DID identities, permissionless delegation and offline verification

Status: implemented in 0.3.0 (Python reference + dependency-free JavaScript). v1
(docs/SPEC-SIGNATURES.md: JWS tokens, v1 schemas and vectors) is unchanged and keeps
verifying; v2 is additive.

**Goal.** Anyone can create an agent identity, delegate authority to another agent and
verify any decision or receipt **without a central registry, issuer or server**. Trust comes
from cryptographic chains back to a root DID that the verifier chooses to pin - never from
asking this service.

Key words MUST, MUST NOT, SHOULD follow RFC 2119. Machine-readable schemas:
`schemas/*.v2.schema.json` (generated from `models_v2.py`). Test vectors:
`tests/vectors/autheo-v2-vectors.json` (checked by Python and `interop/js/verify-v2-vectors.mjs`).
Why these standards: docs/EXISTING-SOLUTIONS.md section "v2 standards decision record".

## 1. Identifiers (DIDs)

| Method | Use | Resolution |
|---|---|---|
| `did:key` (Ed25519, Multikey) | **default** for every agent, principal and environment | pure function of the DID; never networked |
| `did:web` | optional, for principals that need key rotation or a domain-bound identity | offline by default: in-memory map or cache directory; HTTPS fetch only when explicitly enabled |

* A `did:key` is `did:key:z<base58btc(0xed 0x01 || 32-byte Ed25519 public key)>` (multicodec
  ed25519-pub, multibase base58btc). Implementations MUST reject other multicodecs, other
  multibases, wrong lengths and non-canonical encodings (re-encode and compare).
* The DID document of a did:key is generated per the did:key Document Creation Algorithm
  (Multikey form): one verification method `<did>#<fingerprint>`, referenced from
  `authentication`, `assertionMethod`, `capabilityDelegation` and `capabilityInvocation`.
  The X25519 `keyAgreement` key MAY be derived (RFC 7748 birational map); Autheo does not use it.
* `did:web` maps to `https://<host>/.well-known/did.json` or `https://<host>/<path>/did.json`.
  Accepted verification methods: `Multikey` / `Ed25519VerificationKey2020` (publicKeyMultibase,
  Ed25519) and `JsonWebKey` / `JsonWebKey2020` (public OKP Ed25519 JWK). The document id MUST equal
  the DID and the method's controller MUST equal the DID. Fetching (when enabled) uses HTTPS only,
  no redirects, 64 KiB cap, 5 s timeout. **did:web resolution has only been tested offline and
  with a mocked fetcher, never against a live web server.**
* Profile limit: DIDs in v2 documents match `^did:(key|web):[A-Za-z0-9._:-]{1,88}$` (so a DID
  is also a valid v1 identifier; did:web with a port is therefore not usable in v2 documents).
* **Mapping v1 key ids.** A v1 agent kid (`sha256:<b64url(SHA-256(SPKI DER))>`, Paperclip
  format) and a did:key are both functions of the same public key. Given the key (passport
  `public_key` PEM) both can be computed (`did from-key`, identities now report `did`); a kid
  alone cannot be turned into a DID because it is a hash.

## 2. Canonicalization and digests

v2 uses RFC 8785 JSON Canonicalization Scheme (JCS) with an Autheo value profile: integers in
the IEEE-754 safe range only (no floats), no lone surrogates, nesting depth <= 32. Object
members are sorted by UTF-16 code units; strings use ECMAScript escaping (non-ASCII as UTF-8).

`digest(doc) = lowercase_hex(SHA-256(JCS(doc)))` over the complete document including its proof.

(v1's "autheo-cjson/1" additionally ASCII-escapes non-ASCII; it is unchanged for v1.)

## 3. Proofs: W3C Data Integrity, cryptosuite eddsa-jcs-2022

Every signed v2 document carries exactly one `proof` object:

```json
{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2026-09-21T14:13:20Z",
 "verificationMethod": "did:key:z6Mk...#z6Mk...", "proofPurpose": "capabilityDelegation",
 "@context": ["https://www.w3.org/ns/credentials/v2"], "proofValue": "z..."}
```

Signing (Data Integrity EdDSA Cryptosuites v1.0, section 3.3): `proofConfig` = the proof
without `proofValue` (with the document's `@context` copied in when the document has one);
`hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document without proof))`;
`proofValue = "z" + base58btc(Ed25519.sign(hashData))`.

Verification MUST: require exactly one proof object with only the members above; check type,
cryptosuite and the expected `proofPurpose`; parse `created` (format `YYYY-MM-DDTHH:MM:SSZ`);
require a 64-byte signature; if the proof has `@context` it MUST be a prefix of the document's;
resolve `verificationMethod` and check the method is listed under the relationship named by
`proofPurpose`; verify Ed25519. The **controller** of the method (the DID before `#`) is the
signer and MUST equal the document's stated author (`issuer` / `invoker`).

Purposes: delegations `capabilityDelegation`, invocations `capabilityInvocation`, revocations and
receipts `assertionMethod`. The implementation reproduces the W3C specification's eddsa-jcs-2022
example byte-for-byte (included in the vectors).

## 4. Capabilities and attenuation

```json
{"schema_version": "autheo.capability/v2", "environments": ["env:*"], "scopes": ["compute.simulate"],
 "resources": ["listing:*"], "tools": ["git.*"], "asset": "DEMO", "per_action_minor": 80,
 "total_budget_minor": 100, "approval_threshold_minor": 50, "max_delegation_depth": 1}
```

* `environments`, `resources`, `tools` are grant patterns: an exact value, `prefix*` (every value
  starting with prefix) or `*`. `scopes` are the v1 scope names. Lists are unique.
* `approval_threshold_minor <= per_action_minor <= total_budget_minor `; amounts above the
  threshold escalate to human review; `max_delegation_depth` (0-8) is how many further levels
  of sub-delegation are allowed below this grant.

A child capability C is an **attenuation** of parent P iff:
every pattern of C.environments/resources/tools is *covered* by a pattern of P's list
(`*` covers all; `a*` covers `a...` and `a...*`; an exact value covers only itself);
C.scopes ⊆ P.scopes; each of the three amounts of C <= P's; C.validFrom >= P.validFrom and
C.validUntil <= P.validUntil; P.max_delegation_depth >= 1 and C.max_delegation_depth <=
P.max_delegation_depth - 1. Property tests check soundness (a covered pattern never matches a
value its parent does not) and monotonicity (a request permitted by a child is permitted by its parent).

## 5. Delegations (W3C VC 2.0 credentials)

```json
{"@context": ["https://www.w3.org/ns/credentials/v2"],
 "type": ["VerifiableCredential", "AutheoDelegation"],
 "id": "urn:uuid:...", "issuer": "did:key:<delegator>",
 "validFrom": "2026-09-21T14:13:20Z", "validUntil": "2026-09-21T16:13:20Z",
 "credentialSubject": {"id": "did:key:<delegate>", "schema_version": "autheo.delegation/v2",
   "capability": {...}, "parent": {"id": "urn:uuid:<parent id>", "digest": "<digest(parent)>"}},
 "proof": {... "proofPurpose": "capabilityDelegation"}}
```

A conforming VC 2.0 credential (custom terms fall under the base context's `@vocab`). The root
delegation has no `parent`; validity is at most 30 days per link (short TTLs are the main
revocation-lag mitigation; the CLI default is 1 hour).

### 5.1 Chain verification

A chain is `[root, ..., leaf]`, at most 10 links. A verifier, at time `at` with clock skew
`skew` (default 2 s), a set of trusted root DIDs (or explicitly "any root") and a set of
revocation records, MUST report these errors (index = link):

| code | class | condition |
|---|---|---|
| `malformed` | authenticity | schema violation, wrong proof purpose, invalid validity window |
| `bad_signature` | authenticity | proof fails or is not by `issuer` |
| `broken_link` | authenticity | root names a parent; parent id/digest mismatch; issuer is not the parent's subject; parent unverifiable |
| `chain_too_long` | authenticity | > 10 links |
| `invoker_mismatch` | authenticity | invocation signer is not the leaf subject |
| `attenuation_violation` | authorization | any rule of section 4 broken |
| `depth_exceeded` | authorization | parent depth 0, or depth not reduced |
| `not_yet_valid` | authorization | `validFrom > at + skew` |
| `expired` | authorization | `at >= validUntil` |
| `revoked` | authorization | an applicable revocation (section 6) with `revoked_at <= at` |
| `untrusted_root` | authorization | root issuer not pinned |

The chain is **authentic** when there is no authenticity error and **valid** when there is no
error at all. The effective capability is the leaf's (attenuation makes it the narrowest).

## 6. Revocation without a central server

```json
{"type": "AutheoRevocation", "schema_version": "autheo.revocation/v2", "id": "urn:uuid:...",
 "issuer": "did:key:<revoker>", "target": {"id": "urn:uuid:<delegation id>", "digest": "<digest(delegation)>"},
 "revoked_at": "2026-09-21T14:15:00Z", "reason": "compromised", "proof": {... "proofPurpose": "assertionMethod"}}
```

* A record is valid when its proof verifies and is by `issuer`. It is bound to the exact
  credential (id **and** digest).
* It is **applicable** to link *i* of a chain when its issuer is the issuer of link *i* or of any
  ancestor link (0..*i*), or the subject of link *i* renouncing it. Records by anyone else are
  ignored (anyone may *submit* records; only entitled ones have an effect).
* Revoking link *i* invalidates every chain through it (all descendants).
* It takes effect from `revoked_at` (verifiers check `revoked_at <= at`), so historical decisions
  made before a revocation stay verifiable. `revoked_at` is asserted by the revoker; the ledger's
  receipt order is the stronger evidence of when a record became known.

**Distribution.** Records are self-verifying, so they can travel over any channel without
trusting the carrier: the environment's revocation list (`GET /v1/revocations`, `did revocations`,
an unsigned `autheo.revocation-list/v2` container), v2 ledger exports (every accepted record gets
a receipt), the `revocations` array inside decision bundles, or any gossip/file sync. Verifiers
pass whatever records they hold (`--revocations FILE`). **Revocation lag is inherent**: an offline
verifier only knows the records it was given (see docs/THREAT-MODEL.md, "v2").

## 7. Key rotation

* **did:key cannot rotate** - the DID *is* the key. Rotating an agent key means: create a new
  did:key, have the parent issue a new delegation to it, and revoke the old delegation (or let it
  expire; short TTLs make this cheap). Nothing else needs to change because authority lives in the
  chain, not in the identifier.
* A **root** did:key that rotates is a new root: relying parties re-pin (`did trust` /
  `POST /v1/trust-roots`) and the old root revokes its outstanding delegations.
* Principals that need a stable identifier across rotations SHOULD use **did:web**: update the DID
  document (new verification method), keep the DID; previously issued credentials whose proofs
  reference a removed method stop verifying, so re-issue before removing a key.
* Not implemented yet: a signed "rotate to" record on the ledger (old key signs the successor DID,
  relying parties opt in to follow it). Until then, rotation is re-delegation plus revocation.

## 8. Invocations

```json
{"type": "AutheoInvocation", "schema_version": "autheo.invocation/v2", "id": "req:...",
 "invoker": "did:key:<leaf subject>", "environment": "env:research", "action": "compute.simulate",
 "resource": "listing:demo-01", "tool": "git.status", "amount_minor": 20, "asset": "DEMO",
 "created": "...", "expires": "...", "capability": [<root delegation>, ..., <leaf delegation>],
 "proof": {... "proofPurpose": "capabilityInvocation"}}
```

The invoker signs the request **with the full chain embedded**, so the request is
self-contained. Lifetime 1-300 s; a verifier rejects it when `at >= expires` or `created > at +
skew`. `id` is the idempotency key: the environment records at most one decision per id (same
document = replay of the stored receipt, different document = conflict).

## 9. Decisions (the policy decision point)

`POST /v1/invocations/evaluate` / `did evaluate`:

1. Verify the invocation (proof by the invoker, lifetime). Failure: **rejected, not recorded**.
2. Verify the chain at `now` against the environment's trusted roots (`config.json`
   `trusted_roots`, managed with `did trust`) and every revocation record the environment has
   accepted. Authenticity errors: **rejected, not recorded**. Authorization errors: evaluation
   continues and the decision is a recorded **block** with reasons `delegation_<code>:<index>`.
3. Run the declarative policy (v1 engine, unchanged for v1) with the leaf capability as the
   mandate, plus a `chain.environment` check and a **cumulative budget check for every ancestor
   link**: the sum of allowed amounts of all decisions whose chain contains that link, plus this
   amount, must not exceed the link's `total_budget_minor` (reason `chain_budget_limit:<index>`).
   Sibling sub-agents therefore share their parent's budget.
4. Append a receipt (section 10) and return it with a bundle (section 11). Nothing executes.

## 10. Receipts and the v2 ledger

A receipt (`autheo.receipt/v2`, type `AutheoReceipt`) is signed by the environment's did:key
(the environment authority key; `GET /v1/info` `authority_did`) with purpose `assertionMethod` and
contains: `sequence`, `previous_hash`, `recorded_at`, `kind` (`decision`|`revocation`), `decision`,
`reasons`, `document_digest` (digest of the invocation or revocation record), `request_id`,
`invoker`, `root`, `chain` (`[{id, digest, issuer, subject}]`), the request fields, `policy_id`,
`policy_digest`, `reference` (revocation id), `executed: false`, `simulation_only: true`.

Link: `chain_hash(n) = lowercase_hex(SHA-256(ascii(previous_hash) || JCS(signed receipt n)))`,
genesis previous hash = 64 zeros. Stored in the environment's SQLite file in separate tables
(`v2_events`, `v2_revocations`, append-only triggers), so the v1 JWS chain is untouched.
Export: `autheo.ledger-export/v2` `{environment, issuer, head, receipts}`. As in v1 the ledger is
tamper-evident, not tamper-proof: whoever holds the environment key can rewrite it; compare the
head with an independently stored copy (`--expected-head`) to detect truncation.

## 11. Bundles and offline verification

`autheo.bundle/v2` = `{receipt, invocation, revocations}` (revocations: records the environment
knew that target links of this chain). A verifier, with **no network and no service**:

1. validates the structure;
2. verifies the receipt proof (and, if pinned, that `issuer` is the expected environment DID);
   the receipt must be a `decision`;
3. checks `digest(invocation) == receipt.document_digest`;
4. verifies the invocation and its chain **as of `receipt.recorded_at`** using the bundle's
   revocations plus any the verifier holds, against the pinned root DIDs;
5. checks every receipt binding (request id, invoker, environment, action, resource, tool,
   amount, root, chain links) against the invocation and chain;
6. requires the chain to be authentic; computes whether the chain authorizes the request
   (chain valid and the request within the leaf capability);
7. an `allow` receipt MUST be authorized by the chain (`allow_not_supported_by_chain` otherwise).
   `block`/`escalate` receipts are verifiable facts even when the chain does not authorize.

Verdicts: `allow_verified`, `escalate_verified`, `block_verified` or `invalid` with problems such as
`receipt_invalid:bad_signature`, `receipt_invalid:untrusted_issuer`, `invocation_digest_mismatch`,
`receipt_binding_mismatch:<field>`, `allow_not_supported_by_chain`. Stateful limits that need the
ledger (cumulative budgets, rate limits, policy budgets) cannot be re-derived from one bundle;
verify the ledger export for those.

## 12. Interfaces

* **Offline verifier**: `python -m autheo_agent_environment.verifier bundle|chain|invocation|ledger ...`
  (also `autheo-verify` and `did verify ...`); `--root DID` (repeatable) or explicit `--any-root`.
* **JavaScript**: `interop/js/autheo-did.mjs` - `verifyBundle`, `verifyChain`, `verifyInvocation`,
  `verifyReceipts`, `signDocument` (WebCrypto; Node >= 20 and browsers).
* **CLI**: `did create|resolve|from-key|web-cache|delegate|revoke|invoke|verify` (offline) and
  `did trust|evaluate|record-revocation|revocations|ledger` (state directory).
* **HTTP** (loopback, bearer token): `/v1/dids`, `/v1/dids/{did}`, `/v1/trust-roots`,
  `/v1/delegations`, `/v1/delegations/verify`, `/v1/revocations`, `/v1/invocations/evaluate`,
  `/v1/bundles/verify`, `/v1/ledger/v2`, `/v1/schemas/v2/{name}` (docs/openapi.json). Service-held
  DID keys (`POST /v1/dids`) are **local-dev custody** for demos; real agents sign their own
  delegations and invocations and send only signed documents.

## 13. What v2 does not provide

No on-chain or third-party anchoring of ledger heads; no hosted revocation registry or
freshness guarantee (revocation lag is bounded only by TTLs and how records are distributed);
did:web never exercised against a live server; no key custody/HSM/wallet; Data Integrity proof
sets/chains, other cryptosuites and JSON-LD processing are out of profile; no executor - every
decision is a simulation.
