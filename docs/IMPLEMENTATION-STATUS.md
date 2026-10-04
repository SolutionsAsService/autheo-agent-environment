# Delivery / claim ceiling

- Implemented: local signed identity and request proof, finite mandates, strict
  DEMO accounting, allow/escalate/block, idempotency, local revocation, signed
  hash-linked receipts, offline receipt verifier, destination-bound one-time
  checkpoint import, short-lived read-only MCP snapshot export.
- MCP branch: five new read/local-inspection tools and one documentation resource;
  no custody, payment, mandate issuance, approval or live execution tool.
- Existing website: unchanged; it must not advertise this prototype as deployed.
- External deployment: none. No issuer, runtime, wallet or chain service installed.
- Repository: public source prepared for independent review; public availability
  is not a production deployment, security audit, or live integration.
- Verification results are recorded in VERIFICATION.md after final checks.

## Planned direction

The product-level DID, Agent Guardrail Interface, defense-in-depth, Autheo
ecosystem mapping, Hyperliquid adapter example, decision questions, and staged
acceptance gates are documented in [PRODUCT-PLAN.md](PRODUCT-PLAN.md). These are
proposed work, not implemented capabilities. See the
[north-star architecture](AUTHEO-AGENT-TRUST-ARCHITECTURE.svg).
