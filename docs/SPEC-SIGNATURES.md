# Autheo document, signature and receipt-chain specification (v1)

**Status:** stable for schema v1 of this local reference implementation (0.2).
It specifies bytes precisely enough for an independent verifier in another
language. It is not an Autheo platform standard, a DID method or a W3C VC
profile; those remain open owner decisions (see PRODUCT-PLAN.md `12).

Normative artefacts that accompany this text:

| Artefact | Purpose |
| --- | --- |
| `schemas/*.v1.schema.json` | JSON Schema (draft 2020-12) for every document body, the JWS header/claims, ledger rows and policies. Generated from the Pydantic models; CI fails on drift. |
| `tests/vectors/autheo-v1-vectors.json` | Deterministic cross-language vectors: keys, canonical JSON, valid and invalid JWS, a receipt chain and a tampered chain. |
| `interop/js/autheo-verify.mjs` | Dependency-free Node reference verifier; pytest runs it against the vectors. |

The key words MUST, MUST NOT, SHOULD are used as in RFC 2119.

## 1. Signed documents: compact JWS with Ed25519

Every signed Autheo document is an [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)
**compact JWS** using the [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) `EdDSA`
algorithm with an **Ed25519** key (no Ed448, no other algorithm):

```text
BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
```

Base64url is unpadded (RFC 7515 `2). The signature is the 64-byte Ed25519
signature (RFC 8032, pure Ed25519, no pre-hash, empty context) over the ASCII
bytes of `BASE64URL(header) "." BASE64URL(payload)`.

**Verifiers MUST verify over the exact received bytes and MUST NOT
re-serialize JSON before verification.** Issuers produce compact JSON; key
order inside a JWS payload is *not* normative.

### 1.1 Protected header (`schemas/jws-header.v1.schema.json`)

| Member | Value |
| --- | --- |
| `alg` | MUST be `"EdDSA"`. Verifiers MUST reject any other value, including `none` and HMAC algorithms. |
| `typ` | MUST be `"autheo-<kind>+jwt"` for the expected kind (`passport`, `mandate`, `request`, `receipt`, `handoff`, `trust-snapshot`, `outcome`). A token of one kind MUST NOT be accepted as another. |
| `kid` | MUST equal the key id the verifier expects (see `1.3). |
| `crit` | MUST be absent. |

No other header members carry meaning.

### 1.2 Claim set (`schemas/jws-claims.v1.schema.json`)

| Claim | Meaning |
| --- | --- |
| `iss` | Signer identity: the issuer id for authority documents; the **agent id** for agent-signed `request` and `outcome`. |
| `sub` | Subject agent id. |
| `aud` | A single string (never an array): `autheo-agent-environment` for passports, the environment id for mandates/requests/receipts/outcomes, the destination environment for handoffs, `autheo-mcp-readonly` for trust snapshots. |
| `iat`, `nbf` | Integer seconds; `nbf` MUST equal `iat`. |
| `exp` | Integer seconds; `0 < exp - iat <= MAX_TTL[kind]`. |
| `jti` | Non-empty string, unique per document (UUIDv4 in this implementation). Mandate and passport `jti` values are their ids. |
| `body` | JSON object: the kind-specific document validated by `schemas/<kind>.v1.schema.json`. |

`MAX_TTL` (seconds): passport 86400, mandate 3600, request 300, handoff 300,
trust-snapshot 300, receipt 86400, outcome 300.

### 1.3 Key ids and key encoding

* Authority keys: in the persistent state directory `kid = "local-" + first 16
  chars of the key fingerprint`; the ephemeral demos use `"demo-v1"`. The
  verifier is configured with the expected `kid` and public key (the trust
  anchor); a token never selects its own key.
* Agent-signed documents (`request`, `outcome`): `kid` is the fingerprint of the
  passport-bound key, `"sha256:" + BASE64URL(SHA-256(SPKI DER))`. This is the
  same construction Paperclip uses for agent `keyId`. The 0.1 value `"demo-v1"`
  is still accepted for compatibility; any other value is rejected.
* Public keys travel as SPKI PEM (`-----BEGIN PUBLIC KEY-----`). The vectors also
  give the RFC 8037 OKP JWK (`{"kty":"OKP","crv":"Ed25519","x":...}`) and raw hex.

### 1.4 Verification algorithm

Given `token`, expected `kind`, `issuer`, `audience`, public key, `kid`, the
current time `now` and whether this is a **historical** receipt check:

1. Reject tokens over 131072 bytes or without exactly three segments.
2. Decode the header; enforce `1.1`.
3. Verify the Ed25519 signature over the received signing input.
4. Decode claims; all of `iss sub aud iat nbf exp jti body` MUST be present;
   timestamps MUST be integers; `body` MUST be an object.
5. `iss == issuer` and `aud == audience` (string equality).
6. Unless historical: `exp > now` (a token is expired at `exp`).
7. `iat <= now + 2` and `nbf <= now + 2` (two seconds of clock skew, never more).
8. `nbf == iat` and `0 < exp - iat <= MAX_TTL[kind]`.
9. Validate `body` against the kind's schema.

**Historical** verification applies only to receipts: it skips step 6 so an
archived receipt remains verifiable after its `exp`. It proves what the issuer
recorded, never that an external action happened.

## 2. Canonical JSON: `autheo-cjson/1`

Canonical JSON is used **only for digests** (`payload_hash`,
`policy_digest`, `passport_digest`, `request_digest`, checkpoint artefacts), never
for signatures. The canonical form of a value is the ASCII byte string produced by:

* objects: members sorted by key (Unicode code point order; all Autheo keys are
  ASCII), `{"k":v,...}` with no whitespace; keys MUST be strings;
* arrays: `[v,...]` in order, no whitespace;
* strings: `"` + content + `"` where every character outside printable ASCII
  (0x20-0x7E), plus `"` and `\`, is escaped: `\"` `\\` `\b` `\f` `\n` `\r` `\t`
  where those exist, otherwise `\u` + 4 **lowercase** hex digits (DEL 0x7F
  included; code points above U+FFFF as a UTF-16 surrogate pair); `/` is not escaped;
* numbers: integers only, in `[-(2^53-1), 2^53-1]`, decimal without leading
  zeros or `+`; floats, NaN and infinities MUST be rejected;
* `true`, `false`, `null` literals.

`digest(value) = lowercase_hex(SHA-256(canonical_bytes(value)))`. For the
values Autheo emits this equals RFC 8785 (JCS) output after ASCII escaping.
In JavaScript: sort keys, use `JSON.stringify` for strings and replace
`/[\u007f-\uffff]/g` with lowercase `\uXXXX` escapes (see `interop/js`).
JavaScript cannot distinguish `1.0` from `1` after `JSON.parse`; Autheo never emits floats.

Examples (from the vectors): `{"b":1,"a":2,"B":3}` → `{"B":3,"a":2,"b":1}`;
`"café"` → `"caf\u00e9"`; a JWS string digests as the canonical JSON string,
i.e. SHA-256 of `"<token>"` including the quotes.

## 3. Receipts and the hash chain

A receipt is an `autheo-receipt+jwt` signed by the environment authority with
`aud` = environment id and `body` per `schemas/receipt.v1.schema.json`. Each
environment keeps one ordered chain (`schemas/ledger-entry.v1.schema.json` rows):

```text
previous_hash(1)  = "0" * 64
chain_hash(n)     = lowercase_hex(SHA-256(ASCII(previous_hash(n)) || ASCII(receipt_jws(n))))
previous_hash(n+1)= chain_hash(n)
head              = chain_hash(last)   (or "0"*64 for an empty ledger)
```

A verifier MUST check, for every row `n` (1-based): the receipt verifies
historically; `body.sequence == n`; `body.previous_hash == previous_hash(n)`;
the recomputed `chain_hash` equals the stored one; `body.request_id` equals the
row id and is unique; `body.executed == false`; `body.kind` is known.

Receipt kinds: `simulation` (allow/escalate/block decision), `outcome_report`
(executor-reported outcome of an allowed decision, never proof),
`revocation`, `identity_issue`, `mandate_grant`, `handoff_export`,
`handoff_import`. Receipts never claim execution: `executed` is always
`false` and `simulation_only` always `true` in schema v1.

A chain detects edits, insertions and reordering. **It cannot detect a removed
tail or a wholesale replacement** unless the verifier compares the head with an
anchor stored independently of the ledger host (`ledger anchor` /
`--expected-head`).

## 4. Versioning rules

* Body documents carry `schema_version` (e.g. `autheo.receipt/v1`); `$id` values
  are URNs (`urn:autheo:schema:receipt:v1`) — there is no hosted schema registry.
* Within v1, new **optional** fields may be added. Schemas set
  `additionalProperties: false`, so a verifier on an older v1 schema rejects
  unknown fields rather than silently misreading them; upgrade the schema first.
* Removing/renaming a field, changing a meaning, adding a scope to the enumerated
  vocabulary in a way that widens authority, or changing canonicalization/
  signature rules requires v2 with new `typ`/`schema_version` values.
* 0.1 receipts lacked `schema_version` and `recorded_at`; the Python ledger
  verifier still accepts them, the v1 schema does not.

## 5. Regenerating and checking artefacts

```sh
python -m autheo_agent_environment schema export schemas      # or: schema check schemas
python -m autheo_agent_environment vectors generate tests/vectors/autheo-v1-vectors.json
node interop/js/verify-vectors.mjs
```
