## 2026-09-29 -- Separate policy outcomes, execution authority and demo arithmetic
Goal (G): Build an honest reference trust layer and a read-only MCP bridge.
What drifted / what went wrong: An initially selected review example exceeded the cumulative cap after a previous reservation, so the correct policy outcome was block rather than escalation. A signed snapshot also must not be mistaken for an execution grant.
Fix / resolution: Enforced block-before-review precedence, changed demo inputs to satisfy the intended review path, asserted all three expected outcomes in tests, and made execution_authorized/executed false explicit across interfaces.
Generalizes to: Verify stories against stateful policy results; keep authority decisions at the actual execution boundary, never in a stale inspection report.
