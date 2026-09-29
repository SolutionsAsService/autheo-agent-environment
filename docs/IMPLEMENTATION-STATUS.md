# Delivery / claim ceiling

- Implemented: local signed identity and request proof, finite mandates, strict
  DEMO accounting, allow/escalate/block, idempotency, local revocation, signed
  hash-linked receipts, offline receipt verifier, destination-bound one-time
  checkpoint import, short-lived read-only MCP snapshot export.
- MCP branch: five new read/local-inspection tools and one documentation resource;
  no custody, payment, mandate issuance, approval or live execution tool.
- Existing website: unchanged; it must not advertise this prototype as deployed.
- External deployment: none. No issuer, runtime, wallet or chain service installed.
- New project: local source; intended to be independently reviewable before any
  production integration or public publication.
- Verification results are recorded in VERIFICATION.md after final checks.
