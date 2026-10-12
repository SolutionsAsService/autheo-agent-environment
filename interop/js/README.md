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
