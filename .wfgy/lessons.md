## 2026-09-29 -- Separate policy outcomes, execution authority and demo arithmetic
Goal (G): Build an honest reference trust layer and a read-only MCP bridge.
What drifted / what went wrong: An initially selected review example exceeded the cumulative cap after a previous reservation, so the correct policy outcome was block rather than escalation. A signed snapshot also must not be mistaken for an execution grant.
Fix / resolution: Enforced block-before-review precedence, changed demo inputs to satisfy the intended review path, asserted all three expected outcomes in tests, and made execution_authorized/executed false explicit across interfaces.
Generalizes to: Verify stories against stateful policy results; keep authority decisions at the actual execution boundary, never in a stale inspection report.

## 2026-10-12 -- Specify bytes, then prove them from a second language
Goal (G): Make receipts/mandates verifiable outside Python (JARVIS is JavaScript) and turn the simulator into a usable local trust service.
What drifted / what went wrong: A "canonical JSON" description that said "non-ASCII is escaped" was wrong for DEL (0x7F), which Python's ensure_ascii escapes but a naive JS port does not; the first JS verifier also checked historical receipts with now=0, so every receipt looked "not yet valid". Agent-signed tokens also inherited the issuer's demo kid, which made the request kid meaningless.
Fix / resolution: Generated deterministic vectors (fixed seeds, timestamps, jti), wrote a dependency-free Node verifier, ran it from pytest, and fixed the spec to "escape everything outside 0x20-0x7E". Agent kid is now the key fingerprint (Paperclip-compatible); policy outcomes keep 0.1 reason codes under the default policy; lifecycle receipts changed ledger counts, so tests now name that baseline explicitly.
Generalizes to: A cross-language spec is only real when a second implementation passes committed vectors in CI; keep the "decision is not a capability / outcome is a claim" distinction in every new surface.
