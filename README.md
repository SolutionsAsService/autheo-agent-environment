# Autheo Agent Environment — local reference prototype

**Identities, scoped mandates, policy decisions, signed receipts, and controlled task checkpoints.**
Built by **SolutionsAsService** to explore the agent trust-layer vision alongside Autheo MCP.

This is a tested **local simulation**, not a production identity authority, wallet,
sandbox, payment processor, or live agent-migration platform. The existing Autheo
MCP and public website remain separate projects.

## Start here

```sh
python -m venv .venv
# Windows: .venv\Scripts\python.exe; Unix: .venv/bin/python
python -m pip install -e '.[dev]'
python -m autheo_agent_environment.demo --output demo-output
python -m pytest -q
```

Run those Python commands inside the activated environment, or use its executable
path explicitly. Python 3.11+ is required. The demo makes **no network calls**.

The demo:

1. Creates ephemeral Ed25519 issuer and agent keys using `cryptography`.
2. Issues a signed agent passport and a short-lived, resource-scoped mandate.
3. Verifies an agent-signed request using the key bound into its passport.
4. Demonstrates **allow → escalate → block** with a budget of **100 DEMO minor units**.
5. Signs receipts and links them by hashes in a local SQLite ledger.
6. Exports a signed checkpoint to a second environment; it imports **no funds,
   private keys, environment variables, or execution authority**.
7. Exports a 120-second signed **read-only** summary for Autheo MCP.

`allow` only reserves simulated budget. `escalate` creates a review-needed result;
there is no agent-callable approval override. `block` consumes no demo budget.
**No action is actually executed, even when the policy outcome is allow.**

## Outputs

| File in `demo-output/` | Purpose |
| --- | --- |
| `demo-report.json` | Decisions, checkpoint result, audit heads, and MCP environment settings |
| `source-audit.json`, `destination-audit.json` | Signed receipt archives for independent offline verification |
| `issuer-public.pem` | Demo public verification key; **not a wallet or private key** |
| `trust-snapshot.jwt` | Expiring signed summary, not an access token |
| `mcp-environment.json` | Operator configuration for the MCP inspection branch |

Keys and demo databases are temporary and discarded when the demo exits. The
signed receipt archives remain verifiable using the public key. Re-running creates
a **new demo identity** and replaces the export; it is not persistent identity
rotation. Use a fresh output directory to retain an older demonstration.

Verify the source receipt archive:

```sh
python -m autheo_agent_environment.audit demo-output/source-audit.json \
  --public-key demo-output/issuer-public.pem \
  --issuer autheo-demo-authority --environment env:research
```

Supply `--expected-head <head stored separately>` to detect truncation relative
to a previously trusted checkpoint. A head obtained from the same potentially
compromised archive is not an independent witness. Historical receipt verification
checks signatures and links, not current token authorization or real-world action.

## Connect to the MCP prototype

Use current `main` from [ThothDivision/autheo-mcp](https://github.com/ThothDivision/autheo-mcp), which includes the trust inspection tools.
This is **not** an automatically installed OpenClaw connector or a live service.

```sh
git clone https://github.com/ThothDivision/autheo-mcp.git ../autheo-mcp
python -m pip install -e '../autheo-mcp[dev,trust]'
python review/smoke_mcp_bridge.py
```

The bridge test creates fresh demo exports and launches both real MCP stdio entrypoints.
It checks five tools, the documentation resource, simulated budget results, invalid
limits, and tampered snapshots. For a client, merge the entries from
`mcp-environment.json` into the MCP server's environment. Do not upload signing
keys or tokens to a website; private signing keys are never exported here.

New MCP surface:

- `autheo_agent_trust_guide`
- `autheo_agent_trust_status`
- `autheo_agent_get_passport`
- `autheo_agent_get_mandate`
- `autheo_agent_list_receipts`
- `autheo://agent-trust`

Only operator configuration supplies paths, issuer, subject, environment, key ID,
and the public trust anchor. Tool callers cannot choose a different identity or
verification key. Snapshots expire after 120 seconds; rerun the demo to refresh.
Snapshot inspection does **not** enforce policy on existing read-only MCP tools.

## Architecture and next steps

- [Vision mapped into components](docs/VISION-AND-ARCHITECTURE.md)
- [Threat model and honest limits](docs/THREAT-MODEL.md)
- [Implementation phases and acceptance gates](docs/ROADMAP.md)
- [Existing open-source building blocks](docs/EXISTING-SOLUTIONS.md)

Dependencies reuse PyJWT/cryptography for standard JWS/Ed25519 and Pydantic for
strict schemas. The small in-process policy evaluator is an inspectable reference
model; use a governed policy engine and separately isolated issuer/signer in a
production control plane. No custom cryptographic algorithm is implemented.

## Dev Portal / Layer 0

See the [integration design and acceptance gates](docs/DEV-PORTAL-LAYER0.md).
The target integration is planned; this release is still a local reference prototype.

- [Source repository](https://github.com/SolutionsAsService/autheo-agent-environment)
- [Explanatory website source](https://github.com/SolutionsAsService/autheo-agent-environment-site)
- [Autheo MCP](https://github.com/ThothDivision/autheo-mcp)
