# Existing solutions preflight (2026-09-29)

Prefer maintained components for standards and security primitives; custom work
here is limited to the Autheo-specific reference flow and integration contract.

| Component | Existing choice | Decision |
| --- | --- | --- |
| Signatures / JWS | [PyJWT](https://github.com/jpadilla/pyjwt), [cryptography](https://cryptography.io/) | Used now; standard EdDSA JWS and Ed25519, no custom crypto |
| Workload identity | [SPIFFE/SPIRE](https://github.com/spiffe/spire) | Production candidate; not installed or represented as integrated |
| Policy engine | [Open Policy Agent](https://github.com/open-policy-agent/opa) | Production candidate; reference evaluator is deliberately small and local |
| Schema validation | [Pydantic](https://docs.pydantic.dev/) | Used now with strict fields and unknown-field rejection |
| Local atomic state | Python SQLite | Used now for serial simulation accounting and replay protection |
| MCP authorization | [MCP authorization security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) | Audience separation and no token passthrough; report JWS is not transport authorization |

GitHub metadata checked during implementation: OPA and SPIRE were non-archived
Apache-2.0 projects; PyJWT was non-archived MIT. Their activity was current on the
observation date. This is a suitability preflight, not a complete security audit.

The emerging agent-identity platforms found in search were not blindly adopted:
we have not established their maturity, security properties or fit to Autheo's
actual deployment contracts. No paid platform or proprietary identity service was
provisioned. Production choice requires the organization's real identity provider,
agent runtime, custody requirements and compliance constraints.


## v2 standards decision record (2026-10-12, 0.3.0)

Goal: permissionless control - identities, delegation and verification with no registry,
issuer or server. Checked before building:

| Need | Candidates checked | Chosen | Why |
| --- | --- | --- | --- |
| Agent identifiers | W3C DID Core 1.0; did:key (W3C CCG v0.7); did:web; did:peer; did:ion/ledger methods | **did:key (Ed25519, Multikey) default, did:web optional** | did:key is self-generated, needs no registration and resolves as a pure function (offline). did:web adds rotation/domain binding where wanted. Ledger-based methods need a chain or node - not permissionless-offline. |
| Delegation format | UCAN 1.0 (DAG-CBOR envelopes, varsig, CIDs); UCAN 0.10 (JWT); ZCAP-LD (CCG draft); W3C VC Data Model 2.0 | **VC 2.0 credential (`AutheoDelegation`) with UCAN/ZCAP semantics** | VC 2.0 is a W3C Recommendation and plain JSON. UCAN 1.0 would need DAG-CBOR, CIDs and varsig (no maintained Python implementation; large surface); UCAN 0.10 is superseded. ZCAP-LD is an unfinished draft tied to JSON-LD processing. We take the semantics both agree on - issuer/audience DIDs, attenuation, time bounds, proofs embedded in the chain, revocation by an issuer in the chain - and encode them as VCs. |
| Proofs | VC-JOSE/JWT (EdDSA); Data Integrity eddsa-rdfc-2022 (RDF canonicalization); **Data Integrity eddsa-jcs-2022** | **eddsa-jcs-2022** | W3C Recommendation, no JSON-LD/RDF processing (JCS + SHA-256 + Ed25519 only), documents stay readable JSON, and the spec publishes a full example we reproduce byte-for-byte. JWS stays the v1 format. |
| Canonical JSON | RFC 8785 libraries (e.g. `jcs` on PyPI, `canonicalize` on npm) | **~80-line pure implementation per language** | Tiny, auditable, tested against RFC 8785's own examples and property tests; avoids two unaudited dependencies for a function this small. |
| base58btc / multicodec | `base58`, `multiformats` packages | **pure implementations** | A few dozen lines, tested against draft-msporny-base58 vectors and the did:key/W3C keys; `multiformats` would pull in a large dependency tree. |
| Ed25519 / SHA-256 | `cryptography` (Python), WebCrypto (JS) | **same - no custom crypto** | `cryptography` was already a dependency (now explicit); WebCrypto Ed25519 works in Node >= 20 and current browsers, so the JS verifier has zero dependencies. |

Runtime dependencies did not grow (`cryptography` was already installed via `PyJWT[crypto]`);
`hypothesis` was added as a dev/test dependency for property tests. Normative profile:
[SPEC-DID.md](SPEC-DID.md).
