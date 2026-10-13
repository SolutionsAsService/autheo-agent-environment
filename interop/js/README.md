# JavaScript interoperability

Dependency-free Node (>= 20) reference code for verifying Autheo signed documents,
receipt chains and canonical-JSON digests, written against
[docs/SPEC-SIGNATURES.md](../../docs/SPEC-SIGNATURES.md).

```sh
node interop/js/verify-vectors.mjs            # checks tests/vectors/autheo-v1-vectors.json
```

`autheo-sign.mjs` signs agent documents (`signRequest`, `signOutcome`, `keyFingerprint`)
with a runtime-held Ed25519 key; pytest checks that a request signed by it is accepted
by the Python service.

`autheo-verify.mjs` exports `canonicalize`, `digest`, `chainHash`, `verifyJws` and
`verifyChain`. It uses only `node:crypto` (Ed25519 via `crypto.verify(null, ...)`).
The pytest suite runs this script when `node` is on PATH, so Python and JavaScript are
checked against the same committed vectors. It is reference code for integration work
(e.g. the JARVIS kernel), not a published npm package.


## v2: DIDs, delegation chains and offline verification (autheo-did.mjs)

`autheo-did.mjs` is a dependency-free, **isomorphic** implementation of the v2 profile
(docs/SPEC-DID.md). It uses only `globalThis.crypto.subtle` (Ed25519 + SHA-256), so the same
file runs in Node >= 20 and in current browsers (the web demo serves a byte-identical copy
from `src/autheo_agent_environment/web/autheo-did.mjs`; a test enforces that).

```js
import { verifyBundle, verifyChain, verifyInvocation, signDocument } from './autheo-did.mjs';

// Offline: no network, no service. Pin the root DID you trust and (optionally) the environment DID.
const report = await verifyBundle(bundle, { trustedRoots: ['did:key:z6Mk...'], environmentDid: 'did:key:z6Mk...' });
// report.valid, report.verdict ('allow_verified' | 'block_verified' | 'escalate_verified' | 'invalid'),
// report.chain.links (root -> invoker), report.problems
const chain = await verifyChain(chainArray, { at: Math.floor(Date.now() / 1000), trustedRoots: [rootDid], revocations });
```

What it implements: base58btc/multicodec, did:key encode/decode + DID document, did:web URL
mapping (documents only from a caller-supplied map - never fetched), RFC 8785 JCS (safe integers
only), Data Integrity `eddsa-jcs-2022` sign/verify (reproduces the W3C specification example),
the structural rules of every v2 document, attenuation, chain/invocation/revocation/bundle and
v2 ledger verification.

```sh
node interop/js/verify-v2-vectors.mjs      # every v2 vector case must agree with Python
node interop/js/sign-v2-invocation.mjs     # JS-signed invocation; Python checks it is byte-identical
```

v1 (`autheo-verify.mjs`, `verify-vectors.mjs`) is unchanged.

## Package `@autheo/did` (0.6) and trading venues

`interop/js` is an npm-style package: `package.json` exports `autheo-did.mjs` with TypeScript
declarations (`autheo-did.d.mts`); `npm pack` ships only those two files, README and package.json.
It is not published to a registry. Consume it pinned to a commit, either

* vendored: copy `autheo-did.mjs` + `autheo-did.d.mts` and record repo, commit and SHA-256 of each
  file next to them (re-copy and update the record to upgrade), or
* `npm pack` at a tagged commit and install the tarball.

0.6 adds what an external venue (DEX, exchange) needs to act as a decision point for agents
([SPEC-VENUE.md](../../docs/SPEC-VENUE.md)): `decideInvocation` (mandate-only policy, same
outcomes and reasons as Python), `signDecisionReceipt` (venue-signed `autheo.receipt/v2`,
byte-identical to Python's), the `dex.*` scopes and the `asset` budget unit.

```sh
cd interop/js && npm test     # v2 vectors + venue vectors, imported through the package name
```
