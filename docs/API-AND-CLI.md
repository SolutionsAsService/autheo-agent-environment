# Local trust API and CLI (0.2, v2 DID additions in 0.3)

Both surfaces drive the same `TrustService` over a **state directory**. Nothing
is executed: decisions are simulations recorded as signed, hash-chained receipts.

## State directory

```sh
python -m autheo_agent_environment --state-dir .autheo-state init \
  --environment env:research --environment env:review
```

Creates (0700/0600 where supported): `config.json`, `issuer-key.pem` (**local
development issuer key, unencrypted** — not production custody),
`issuer-public.pem` (trust anchor), `api-token`, `policy.yaml`, `registry.db`
(mutable index of passports/mandates) and one append-only `ledger-<env>.db` per
environment. `AUTHEO_STATE_DIR` overrides the default `./.autheo-state`. The
ephemeral mode (web demo, tests) uses the same layout in a temporary directory.

## CLI

All commands print JSON; errors print `{"error","detail"}` on stderr and exit 2;
`ledger verify` exits 1 when verification fails.

| Command | Purpose |
| --- | --- |
| `init`, `info` | Create state; show issuer, kid, public key, environments, policy digest |
| `identity issue --agent-id --owner-id --environment ... (--public-key-file F \| --generate-key)` | Issue a passport. Prefer an agent-held key; `--generate-key` stores the agent key in the state dir (local-dev custody) |
| `identity show ID` / `identity revoke ID` | Status; revoke the passport in every environment |
| `mandate grant ... --scope --resource [--tool] [--destination] --per-action --total --threshold [--ttl]` | Signed mandate (max 3600 s) |
| `mandate show ID` / `mandate list` / `mandate revoke ID [--reason]` | Spent/remaining/revoked; revocation is a signed receipt |
| `evaluate --request-token-file F` | Evaluate an agent-signed `autheo-request+jwt` |
| `evaluate --agent-id --mandate-id --action --resource [--tool] [--amount] [--request-id]` | Same, signed with a service-held key (local dev only) |
| `outcome --environment --request-id --status succeeded\|failed\|unknown [--detail-sha256] [--report-token-file]` | Record an executor-reported outcome for an **allowed** decision |
| `receipt verify FILE` / `receipt list --environment` | Signature + ledger membership; recent receipts |
| `ledger verify --environment [--expected-head H \| --anchor F]` | Signatures, links, identity metadata, triggers, optional anchor |
| `ledger anchor --environment --output F` | Write the head to store **elsewhere** |
| `ledger export --environment --output F` | Receipt archive for `python -m autheo_agent_environment.audit` |
| `checkpoint ...` / `handoff accept --token-file --allowed-scope` | Destination-bound checkpoint; grants no authority |
| `policy show` / `policy validate FILE` | Active policy; validate a file |
| `schema export\|check DIR`, `vectors generate\|check F`, `openapi write\|check F` | Contract artefacts and drift checks |
| `serve [--host 127.0.0.1] [--port 8780]` | Run the HTTP API |
| `demo`, `web` | Ephemeral walkthroughs (unchanged story; web now uses the API) |

## HTTP API

`python -m autheo_agent_environment serve` binds **127.0.0.1:8780**. Non-loopback
binds are refused unless `--allow-remote` is passed (there is no TLS — do not do
this outside a lab). The full contract is `docs/openapi.json` (OpenAPI 3.1,
generated from the models; also served at `/v1/openapi.json`).

* Auth: `Authorization: Bearer <contents of api-token>` on every route except
  `/v1/health`, `/v1/openapi.json`, `/v1/schemas[/name]`.
* Host must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` (DNS
  rebinding defence, 421 otherwise); an `Origin` header must be same-origin (403);
  no CORS headers are sent.
* JSON only (415), max 64 KiB (413), unknown fields rejected (400).
* Errors: `{"error": code, "detail"?}` — 400 validation/signature/expiry/policy
  input, 401 auth, 404 unknown id/route, 409 idempotency or replay conflict.

| Method & path | Operation |
| --- | --- |
| `POST /v1/identities` | Issue identity (`public_key` or `generate_key`) |
| `GET /v1/identities/{agent_id}`, `POST .../revoke` | Status / revoke |
| `POST /v1/mandates` | Grant mandate |
| `GET /v1/mandates/{id}`, `POST .../revoke` | Status / revoke |
| `POST /v1/evaluate` | `{"request_token"}` or `{"request": {...}}` → decision + explanation + receipt |
| `POST /v1/receipts/outcome` | Record outcome receipt |
| `POST /v1/receipts/verify` | Verify a receipt token |
| `GET\|POST /v1/ledger/verify`, `GET /v1/ledger/receipts` | Ledger report; recent receipts |
| `POST /v1/checkpoints`, `POST /v1/handoffs/accept` | Checkpoint export / admission |
| `GET /v1/info`, `GET /v1/policy` | Trust anchor and active policy |

Example:

```sh
TOKEN=$(cat .autheo-state/api-token)
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"request_token":"<agent-signed JWS>"}' http://127.0.0.1:8780/v1/evaluate
```

The response's `decision` is a policy-decision-point result
(`is_capability: false`, `executed: false`). It is not a token to present
later: an executor must evaluate immediately before acting and must not cache
an allow.


## v2: DIDs, delegation, revocation (0.3)

Normative rules: [SPEC-DID.md](SPEC-DID.md).

| CLI (`python -m autheo_agent_environment did ...`) | Needs state? | Purpose |
| --- | --- | --- |
| `create --out key.json` / `create --service` | no / yes | New did:key (file key, or local-dev custody in the state dir) |
| `resolve DID [--did-web-cache DIR] [--allow-network]` | no | DID document |
| `from-key --public-key-file PEM` | no | v1 public key -> did:key + v1 kid |
| `web-cache add DOC --did-web-cache DIR` | no | Pin a did:web document for offline use |
| `delegate --key K --to DID [--parent CHAIN] ...` | no | Sign an attenuated delegation; writes the chain |
| `revoke --key K --chain CHAIN [--index N]` | no | Sign a revocation record |
| `invoke --key K --chain CHAIN --environment E --action A --resource R ...` | no | Sign an invocation embedding the chain |
| `verify bundle|chain|invocation|ledger ...` | no | The offline verifier (same as `python -m autheo_agent_environment.verifier` / `autheo-verify`) |
| `trust --environment E --root DID [--remove]` | yes | Pin/unpin a root DID for an environment |
| `evaluate --invocation FILE [--bundle-out FILE]` | yes | Decide, record a v2 receipt, emit a bundle |
| `record-revocation FILE` | yes | Record a signed revocation in every environment |
| `revocations --environment E [--out FILE]` | yes | Export the revocation list |
| `ledger export|verify --environment E [--expected-head H]` | yes | v2 receipt chain |

| HTTP | Purpose |
| --- | --- |
| `POST /v1/dids`, `GET /v1/dids` | Create (local-dev custody) / list service-held DIDs |
| `GET /v1/dids/{did}` | Resolve (did:key offline, did:web cache-only unless `"did_web_network": true` in config.json) |
| `POST /v1/trust-roots` | `{environment, did, trusted}` |
| `POST /v1/delegations` | Sign with a service-held issuer key: `{issuer, subject, capability, parent_chain, ttl_seconds}` |
| `POST /v1/delegations/verify` | `{chain, trusted_roots | any_root, at, revocations}` - pure |
| `POST /v1/revocations`, `GET /v1/revocations?environment=` | Record `{revocation}` or sign `{issuer, chain, index, reason}`; list |
| `POST /v1/invocations/evaluate` | `{invocation}` (agent-signed) or `{request}` (service-held invoker key); returns outcome, reasons, receipt, bundle |
| `POST /v1/bundles/verify` | `{bundle, trusted_roots | any_root, environment_did, revocations}` - pure |
| `GET /v1/ledger/v2?environment=` | v2 ledger export; `GET /v1/ledger/verify` now includes a `v2` section |
| `GET /v1/schemas/v2/{name}` | v2 JSON Schemas |

Errors: invalid proofs return 400 `{"error": "proof_invalid", "code": ...}` (forged chains also list
`errors` per link); invalid DIDs 400 `did_invalid`. Authentic but unauthorised chains (expired,
revoked, widened, untrusted root) are **recorded block decisions**, not errors.
