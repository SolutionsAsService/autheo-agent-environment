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
