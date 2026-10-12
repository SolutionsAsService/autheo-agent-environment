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
path explicitly. Python 3.11+ is required. The CLI demo makes **no network
calls**; the browser walkthrough serves its UI locally over loopback only.

Start the interactive browser walkthrough with:

```sh
python -m autheo_agent_environment.webapp
```

Open `http://127.0.0.1:8765/`. The web demo binds only to loopback, creates
ephemeral identities and a temporary local ledger, and clears its state when the
server stops. It uses the same policy simulator as the CLI; its DIDs are local
did:key identities (nothing is registered), and it does not connect to Autheo, approve
an escalation, or execute a tool, workload, or transaction. To choose another local port, use `--port 8766`.

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

## Permissionless control with DIDs (0.3, v2)

Anyone can create an agent identity, delegate authority and verify any decision -
**without a registry, issuer or server**. Identities are `did:key` DIDs generated locally;
authority is a chain of signed, attenuated delegation credentials (W3C VC 2.0 + Data
Integrity `eddsa-jcs-2022`) back to a root DID the verifier pins; revocations are signed
records anyone can relay.

```sh
D="python -m autheo_agent_environment did"
$D create --out human.json        # did:key, offline; private key stays in the file (0600)
$D create --out agent.json
$D create --out sub.json
$D delegate --key human.json --to did:key:<agent> --environment 'env:*' --scope compute.simulate \
   --resource 'listing:*' --per-action 80 --total 100 --threshold 50 --depth 1 --out chain1.json
$D delegate --key agent.json --to did:key:<sub> --parent chain1.json --environment env:research \
   --scope compute.simulate --resource listing:demo-01 --per-action 30 --total 50 --threshold 20 \
   --out chain2.json               # can only narrow; widening is refused and rejected by verifiers
$D invoke --key sub.json --chain chain2.json --environment env:research \
   --action compute.simulate --resource listing:demo-01 --amount 20 --out inv.json
$D verify chain inv.json --root did:key:<human>          # offline, no state, no network
# With a local environment (records a signed v2 receipt and returns an offline bundle):
$D trust --environment env:research --root did:key:<human>
$D evaluate --invocation inv.json --bundle-out bundle.json
python -m autheo_agent_environment.verifier bundle bundle.json --root did:key:<human>
$D revoke --key agent.json --chain chain2.json --out rev.json && $D record-revocation rev.json
```

- [v2 specification](docs/SPEC-DID.md) · [standards decision record](docs/EXISTING-SOLUTIONS.md)
  · [threat model](docs/THREAT-MODEL.md) · [v2 schemas](schemas/) ·
  [v2 vectors](tests/vectors/autheo-v2-vectors.json) · [JS verifier](interop/js/autheo-did.mjs)
- The browser demo has a "Delegation chains between DIDs" panel: human -> agent -> sub-agent,
  allowed/blocked actions, a revocation, and bundles verified **in the browser** via WebCrypto.
- Not real yet: no on-chain anchoring, no revocation freshness guarantee (keep TTLs short),
  did:web untested against live servers, demo DID keys are unencrypted local files.

## Local trust service (0.2)

The same engine now runs as a persistent, local-first trust layer for agent
runtimes such as JARVIS and Paperclip. It is still a reference implementation:
file-based dev keys, DEMO units, no wallet/payment, and nothing is executed.

```sh
A="python -m autheo_agent_environment --state-dir .autheo-state"
$A init                                   # dev issuer key, API token, policy.yaml, ledgers
$A identity issue --agent-id agent:jarvis-1 --owner-id human:operator \
   --environment env:research --public-key-file agent-public.pem
$A mandate grant --agent-id agent:jarvis-1 --environment env:research \
   --scope tool.invoke --resource repo:jarvis --tool git.status \
   --per-action 50 --total 100 --threshold 40
$A evaluate --request-token-file request.jwt   # agent-signed; prints decision + explanation + receipt
$A ledger verify --environment env:research    # exit 1 on tampering
$A serve                                       # loopback API on 127.0.0.1:8780 (bearer token)
```

- [API and CLI reference](docs/API-AND-CLI.md) · [OpenAPI 3.1](docs/openapi.json)
- [Declarative policy](docs/POLICY.md): scopes, tools, resources, budgets, rate
  limits, time windows, escalation, explanations
- [Signature, canonical JSON and receipt-chain spec](docs/SPEC-SIGNATURES.md),
  [JSON Schemas](schemas/), [cross-language vectors](tests/vectors/autheo-v1-vectors.json),
  [JavaScript verifier/signer](interop/js/)
- [JARVIS and Paperclip integration notes](docs/INTEGRATIONS.md)

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

- [Product plan, current-state audit, DID model, security layers, Hyperliquid flow, and phased acceptance gates](docs/PRODUCT-PLAN.md)
- [Autheo Agent Trust north-star architecture diagram](docs/AUTHEO-AGENT-TRUST-ARCHITECTURE.svg)
- [Vision mapped into components](docs/VISION-AND-ARCHITECTURE.md)
- [Threat model and honest limits](docs/THREAT-MODEL.md)
- [Implementation phases and acceptance gates](docs/ROADMAP.md)
- [Existing open-source building blocks](docs/EXISTING-SOLUTIONS.md)
- [Current claim ceiling](docs/IMPLEMENTATION-STATUS.md) and [verification record](docs/VERIFICATION.md)

The next proposed work is contract discovery with Autheo identity, Dev Portal,
Marketplace, Layer 1, and compute-mesh owners. The roadmap intentionally does not
assume a DID method, chain interface, Hyperliquid endpoint, or production executor
that has not been confirmed.

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
