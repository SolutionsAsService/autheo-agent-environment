# Toward a true DID agent environment on a post-quantum architecture

Status as of 0.5.0 (2026-10-12). This is the gap analysis and plan; claims about
what is implemented are kept in [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md).

## Where we are

| Layer | Today | Quantum-safe? |
| --- | --- | --- |
| Identifiers | did:key (Ed25519) for every principal/agent/environment, offline did:web | No (Ed25519) |
| Delegation | W3C VC 2.0 `AutheoDelegation` chains, attenuation, offline verification | No (eddsa-jcs-2022) |
| Revocation | signed revocation records + lists, no hosted status service | No |
| Decisions & receipts | environment-signed, hash-linked v2 receipts, SQLite ledger | Hashes yes (SHA-256), signatures no |
| v1 compatibility | JWS EdDSA passports/mandates | No |
| **0.4–0.5 experimental** | ML-DSA-44/65/87 did:key and `mldsa{44,65,87}-jcs-2024` proofs, hybrid proof sets, cross-signed `AutheoKeyBinding`, verifier policies classical/hybrid/pq + minimum NIST category, tunable security profiles, hybrid X25519+ML-KEM-768/1024 sealed envelopes, Python + Node vectors | **Yes (hybrid), not yet wired into chains** |

SHA-256 digests and hash chains are fine against quantum attackers (Grover only
halves security to ~128 bits). The exposure is every **signature**: an attacker who
records today's delegations and receipts can forge them once Ed25519 falls, and
receipts are meant to be long-lived evidence. That makes migration urgent for
the evidence layer even before agents move real value.

## What "true DID agent environment" still needs (beyond PQC)

1. **Real principals, not demo keys** — Autheo Identity credentials for humans and
   organisations; agent DIDs issued under an org DID; holder binding and consent.
2. **Key custody** — HSM/KMS/wallet signers behind the `DidSigner` interface;
   no plaintext key files outside dev; per-agent short-lived session keys.
3. **Rotation and recovery** — did:key cannot rotate. Adopt an updatable method
   for long-lived principals (did:webvh or an Autheo L1 DID method with
   pre-rotation commitments), keep did:key for ephemeral agents.
4. **Status and revocation at scale** — Bitstring Status List / a status service
   with freshness guarantees; anchoring of revocation and ledger heads on Autheo L1.
5. **Approval workflow** — request-digest-bound human approvals so `escalate`
   resolves without a new mandate.
6. **Executors that enforce** — the policy decision is checked again at each
   consequential tool/runtime immediately before dispatch (JARVIS, MCP, Paperclip).
7. **Transport security** — TLS/mTLS between services; DIDComm v2 or signed HTTP
   messages for agent-to-agent; multi-tenant isolation.
8. **Privacy** — selective disclosure (SD-JWT VC or BBS) for credentials that
   carry personal data.

## PQC migration plan

| Phase | Deliverable | Gate |
| --- | --- | --- |
| **P0 · crypto agility** (done in 0.4, experimental) | Suite registry (eddsa-jcs-2022, mldsa44-jcs-2024), ML-DSA did:key, hybrid proof sets, key binding, verifier policy, cross-language vectors | Hybrid stripping, unbound keys, tampering, wrong purpose rejected; Python == Node |
| **P1 · hybrid delegation** | `delegate` / `invoke` / revocation / receipts can carry hybrid proof sets; chain verifier enforces per-environment policy (`classical` → `hybrid`); `did bind` CLI + API; trusted roots declared with both keys | v2 vectors byte-identical; new v3 vectors for hybrid chains; downgrade tests |
| **P2 · PQ key exchange** | ML-KEM-768/1024 (+X25519 hybrid) for keyAgreement and encrypted checkpoints/handoffs (envelopes done in 0.5); TLS with hybrid X25519MLKEM768, pure MLKEM1024 under `max` (draft-ietf-tls-mlkem); zkTLS data attestations | Interop with OpenSSL 3.5 / Node 24; no classical-only fallback when policy is hybrid |
| **P3 · PQ by default** | Environments require `hybrid` for new delegations and receipts; ledger anchors signed hybrid; SLH-DSA (hash-based) for long-lived root/anchor keys | Migration runbook; re-sign archives; monitoring of classical-only traffic |
| **P4 · PQ-only option** | Policy `pq` for regulated tenants; classical proofs accepted only for legacy read-back | External review / audit; NIST CNSA 2.0 alignment |

### Open decisions
- **Suite identifiers**: `mldsa44-jcs-2024` follows the W3C CCG *Quantum-Safe
  Cryptosuites* draft; multicodec `0x1210` (mldsa-44-pub) is draft. Track both and
  keep a version gate before calling anything stable.
- **Security level**: ML-DSA-44 (category 2) for agents; ML-DSA-65/87 or SLH-DSA
  for roots and anchors?
- **DID size**: ML-DSA did:key strings are ~1.8 KB. For long-lived identities use
  did:web / an L1 DID with the key in the document instead of in the identifier.
- **Browser verification**: WebCrypto has no ML-DSA yet; ship a WASM verifier or
  verify server-side until browsers catch up.
- **Autheo L1 / L0**: which chain anchors status lists and ledger heads, and with
  which signature scheme on-chain.

## Tunable key strength (0.5)

Strength is a deployment choice, not a constant. `profiles.py` bundles signature strength,
KEM strength and verifier policy; `AUTHEO_SECURITY_PROFILE` (or a per-environment/tenant
setting) selects one, and `custom_profile()` allows fine tuning with validation.

| Profile | Signature | KEM | NIST cat. | PQ pub key / signature | Hybrid proof set size* | Trade-off |
| --- | --- | --- | --- | --- | --- | --- |
| `compact` | ML-DSA-44 | ML-KEM-768 | 2 | 1312 B / 2420 B | ≈ 5.3 KB | smallest and fastest; agent-to-agent traffic, short-lived credentials, constrained devices |
| `balanced` (default) | ML-DSA-65 | ML-KEM-768 | 3 | 1952 B / 3309 B | ≈ 7.1 KB | NIST's general-purpose recommendation; delegations, receipts, institutional APIs |
| `max` | ML-DSA-87 | ML-KEM-1024 | 5 | 2592 B / 4627 B | ≈ 9.7 KB | largest margin, CNSA 2.0 parameter sets; roots, long-lived evidence, banking anchors |

\* base58 proofValue plus proof metadata for Ed25519 + ML-DSA. Verifiers enforce
`min_category`: a weaker post-quantum proof is rejected, never silently accepted, so a
tenant on `max` cannot be downgraded by a sender on `compact`. Signing cost grows roughly
1.5–2× per step; all three verify in well under a millisecond on server hardware.
SLH-DSA (hash-based, very small keys, 8–50 KB signatures) remains the planned option for
offline root/anchor keys; `cryptography` does not ship it yet (Node 24 does).

## Post-quantum transport: ML-KEM in TLS 1.3 (draft-ietf-tls-mlkem)

Tracked fork: [SolutionsAsService/draft-ietf-tls-mlkem](https://github.com/SolutionsAsService/draft-ietf-tls-mlkem)
(IETF TLS WG draft *ML-KEM Post-Quantum Key Agreement for TLS 1.3*: standalone
`MLKEM512/768/1024` key-exchange groups).

How it fits:
- **Phase P2 default = hybrid**, not pure: TLS between agents, environments, the kernel and
  bank-facing APIs negotiates `X25519MLKEM768` (draft-ietf-tls-ecdhe-mlkem; already in
  OpenSSL 3.5, Node 24, Go, Chrome, Cloudflare). Security holds if either half holds.
- **Pure `MLKEM1024` (this draft)** is offered only under the `max` profile / `pq` policy,
  for regulated tenants that require CNSA 2.0-style PQ-only key exchange, once the draft and
  library support stabilise. It removes the classical dependency but has no fallback if
  ML-KEM is ever weakened — the reason it is opt-in.
- Application layer already matches it: `kem.py` seals checkpoint/handoff payloads with
  X25519+ML-KEM-768/1024 using the same hybrid construction, so data stays confidential even
  when it is stored or relayed outside a TLS session.
- Gate: interop tests against OpenSSL 3.5 / Node 24 with `groups = X25519MLKEM768[:MLKEM1024]`;
  policy refuses classical-only handshakes when the profile requires PQ.

## zkTLS: verifiable web data for agents (provenance, not identity)

Tracked fork: [SolutionsAsService/zktls](https://github.com/SolutionsAsService/zktls)
(the3cloud zkTLS 0.2.5, Rust: proves a TLS session and response inside a zkVM — RISC Zero or
SP1 — and exports on-chain verifiers for EVM, Solana, Sui, Aptos, TON).

What it adds: an agent can prove *"this HTTPS endpoint returned this value"* (an account
balance, a KYC status, an exchange rate, a reserve attestation) without the verifier trusting
the agent and without revealing the agent's credentials or the full response.

How it fits:
- New credential type `AutheoTlsAttestation` (P1/P2): subject = server name, request
  template hash, extracted fields, time; evidence = zkTLS proof reference + verifier id;
  signed by the environment with the tenant's profile (hybrid ML-DSA). Policies can then
  require "balance ≥ X, proven by zkTLS from bank Y within 5 min" before allowing an action.
- Receipts reference the attestation, so evidence of *why* an agent acted is verifiable later.
- Anchoring: proof verification on Autheo L1 / L0 Mesh destination chains (the repo already
  exports multi-chain verifiers).

Caveats (why it is a later phase): the proved TLS session uses today's classical TLS and
certificate signatures; zkVM proofs wrapped into Groth16/PLONK for cheap on-chain checks are
**not** quantum-safe (STARK proofs, hash-based, are the PQ-plausible path); proving is heavy
(GPU, minutes); and the upstream is a young project. Use it for freshness-bounded data
provenance, keep identity and authorization on DIDs + ML-DSA.

## Same architecture for the banking solution

The TaaS / banking platform reuses these layers: institutions pick a security profile
(`balanced` default, `max` for custodians and settlement anchors), bank APIs and the L0 Mesh
use hybrid PQ TLS, settlement and audit records carry hybrid signatures, and zkTLS
attestations feed proof-of-reserves, bank-balance and KYC-status checks into compliance
policy without exposing customer data.
