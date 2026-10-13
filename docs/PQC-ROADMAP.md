# Toward a true DID agent environment on a post-quantum architecture

Status as of 0.4.0 (2026-10-12). This is the gap analysis and plan; claims about
what is implemented are kept in [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md).

## Where we are

| Layer | Today | Quantum-safe? |
| --- | --- | --- |
| Identifiers | did:key (Ed25519) for every principal/agent/environment, offline did:web | No (Ed25519) |
| Delegation | W3C VC 2.0 `AutheoDelegation` chains, attenuation, offline verification | No (eddsa-jcs-2022) |
| Revocation | signed revocation records + lists, no hosted status service | No |
| Decisions & receipts | environment-signed, hash-linked v2 receipts, SQLite ledger | Hashes yes (SHA-256), signatures no |
| v1 compatibility | JWS EdDSA passports/mandates | No |
| **0.4 experimental** | ML-DSA-44 did:key, `mldsa44-jcs-2024` proofs, hybrid proof sets, cross-signed `AutheoKeyBinding`, verifier policies classical/hybrid/pq, Python + Node vectors | **Yes (hybrid), not yet wired into chains** |

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
| **P2 · PQ key exchange** | ML-KEM-768 (+X25519 hybrid) for keyAgreement and encrypted checkpoints/handoffs; TLS with hybrid X25519MLKEM768 groups | Interop with OpenSSL 3.5 / Node 24; no classical-only fallback when policy is hybrid |
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
