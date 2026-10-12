"""Single-host reference control plane. All actions and balances are simulations.

The environment is a policy decision point plus a signed, hash-chained receipt
ledger. It never executes an action: "allow" reserves simulated DEMO budget and
an executor (for example the JARVIS kernel) remains responsible for re-checking
and dispatching. Outcome reports from an executor are recorded as claims, not
as proof that anything happened.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from .canonical import ZERO_HASH, chain_hash, digest
from .errors import ConflictError, NotFoundError
from .models import (
    RECEIPT_KINDS,
    Checkpoint,
    Handoff,
    Mandate,
    OutcomeReport,
    Passport,
    ReceiptBody,
    Request,
)
from .policy import DEFAULT_POLICY, PolicyDocument, PriorEvent, evaluate
from .signing import LEGACY_KID, Signer, agent_kid, public_pem, read_public, verify

ZERO = ZERO_HASH
__all__ = ["Environment", "LEGACY_KID", "ZERO"]

APPEND_ONLY_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS events_append_only_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'autheo ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_append_only_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'autheo ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS revoked_append_only_update BEFORE UPDATE ON revoked
BEGIN SELECT RAISE(ABORT, 'autheo revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS revoked_append_only_delete BEFORE DELETE ON revoked
BEGIN SELECT RAISE(ABORT, 'autheo revocations are append-only'); END;
"""


class Environment:
    def __init__(
        self,
        path: Path,
        environment_id: str,
        authority: Signer,
        policy: PolicyDocument | None = None,
        append_only: bool = False,
    ):
        self.path, self.environment_id, self.authority = Path(path), environment_id, authority
        self.policy = policy or DEFAULT_POLICY
        self._temporary = None
        with closing(self.connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    token TEXT NOT NULL, chain_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS revoked (jti TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            if append_only:
                db.executescript(APPEND_ONLY_TRIGGERS)
            expected = {
                "environment": environment_id,
                "issuer": authority.issuer,
                "key": digest(public_pem(authority.public_key)),
            }
            current = dict(db.execute("SELECT name, value FROM metadata"))
            if current and current != expected:
                raise ValueError("Database belongs to a different environment or signing identity")
            db.executemany("INSERT OR IGNORE INTO metadata VALUES (?, ?)", expected.items())

    @classmethod
    def ephemeral(cls, environment_id: str, authority: Signer, policy: PolicyDocument | None = None):
        """Throw-away ledger in a temporary directory; call close() to delete it."""
        temporary = TemporaryDirectory(prefix="autheo-agent-ephemeral-")
        environment = cls(Path(temporary.name) / "ledger.db", environment_id, authority, policy)
        environment._temporary = temporary
        return environment

    def close(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    def connect(self):
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def owner_document(self, token, kind, audience):
        return verify(
            token, kind, self.authority.public_key, self.authority.issuer, audience, self.authority.kid
        )

    # ------------------------------------------------------------------ revocation
    def revoke(self, jti: str, *, agent_id: str | None = None, reason: str = "operator_revoked"):
        """Trusted local operator operation, not exposed to agents or MCP.

        With agent_id the revocation is also recorded as a signed ledger receipt.
        """
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (jti,))
            if agent_id is None:
                return None
            events = self.read_events(db)
            existing = next((e for e in events if e["request_id"] == "revoke:" + jti), None)
            if existing:
                return {**existing, "replayed": True}
            return self.append(
                db,
                events,
                request_id="revoke:" + jti,
                payload_hash=digest({"revoked": jti, "reason": reason}),
                agent_id=agent_id,
                mandate_id=jti,
                kind="revocation",
                decision="revoked",
                reasons=[reason],
                reference=jti,
            )

    def record_event(self, *, request_id, payload_hash, agent_id, mandate_id, kind, reasons, reference=None):
        """Append an operator lifecycle event (identity_issue / mandate_grant). Idempotent per id."""
        with self.transaction() as db:
            events = self.read_events(db)
            existing = next((e for e in events if e["request_id"] == request_id), None)
            if existing:
                if existing["payload_hash"] != payload_hash:
                    raise ConflictError("Lifecycle event id reused for different content")
                return {**existing, "replayed": True}
            return self.append(
                db,
                events,
                request_id=request_id,
                payload_hash=payload_hash,
                agent_id=agent_id,
                mandate_id=mandate_id,
                kind=kind,
                decision="recorded",
                reasons=reasons,
                reference=reference,
            )

    @staticmethod
    def is_revoked(db, *ids):
        return any(db.execute("SELECT 1 FROM revoked WHERE jti=?", (jti,)).fetchone() for jti in ids)

    def revoked(self, *ids) -> bool:
        with closing(self.connect()) as db:
            return self.is_revoked(db, *ids)

    def credentials(self, passport_token, mandate_token, audience=None):
        passport_claims = self.owner_document(passport_token, "passport", "autheo-agent-environment")
        mandate_claims = self.owner_document(mandate_token, "mandate", audience or self.environment_id)
        passport = Passport.model_validate(passport_claims["body"])
        mandate = Mandate.model_validate(mandate_claims["body"])
        if not (
            passport.agent_id == mandate.agent_id == passport_claims["sub"] == mandate_claims["sub"]
            and passport.owner_id == mandate.owner_id
            and mandate.environment == (audience or self.environment_id)
            and mandate.environment in passport.environments
        ):
            raise ValueError("Passport, owner, mandate, and environment do not match")
        read_public(passport.public_key)
        return passport_claims, passport, mandate_claims, mandate

    # ------------------------------------------------------------------ ledger
    def read_events(self, db):
        previous, events = ZERO, []
        for sequence, request_id, token, stored_hash in db.execute("SELECT * FROM events ORDER BY sequence"):
            claims = verify(
                token,
                "receipt",
                self.authority.public_key,
                self.authority.issuer,
                self.environment_id,
                self.authority.kid,
                historical=True,
            )
            body = claims["body"]
            if (
                sequence != len(events) + 1
                or body.get("sequence") != sequence
                or body.get("previous_hash") != previous
                or body.get("request_id") != request_id
                or chain_hash(previous, token) != stored_hash
                or body.get("executed") is not False
                or body.get("kind") not in RECEIPT_KINDS
            ):
                raise ValueError("Audit chain integrity failure")
            events.append({**body, "hash": stored_hash})
            previous = stored_hash
        return events

    def audit(self, expected_head=None):
        with closing(self.connect()) as db:
            events = self.read_events(db)
        head = events[-1]["hash"] if events else ZERO
        if expected_head is not None and head != expected_head:
            raise ValueError("Audit head differs from external checkpoint")
        return {
            "head": head,
            "count": len(events),
            "tamper_evident": True,
            "immutable": False,
            "externally_anchored": False,
        }

    def verify_ledger(self, expected_head=None) -> dict:
        """Full, non-raising verification report (see ledger.verify_database)."""
        from .ledger import verify_database

        return verify_database(
            self.path,
            self.authority.public_key,
            self.authority.issuer,
            self.environment_id,
            self.authority.kid,
            expected_head=expected_head,
        )

    def receipts(self, limit: int | None = None, agent_id: str | None = None) -> list[dict]:
        with closing(self.connect()) as db:
            events = self.read_events(db)
            tokens = dict(db.execute("SELECT sequence, token FROM events"))
        selected = [e for e in events if agent_id is None or e["agent_id"] == agent_id]
        if limit is not None:
            selected = selected[-limit:]
        return [{"receipt": e, "token": tokens[e["sequence"]]} for e in selected]

    def receipt(self, request_id: str) -> dict | None:
        with closing(self.connect()) as db:
            events = self.read_events(db)
            row = db.execute("SELECT token FROM events WHERE request_id=?", (request_id,)).fetchone()
        event = next((e for e in events if e["request_id"] == request_id), None)
        return None if event is None else {"receipt": event, "token": row[0]}

    def verify_receipt(self, token: str) -> dict:
        """Check a receipt's signature (historical) and whether it is part of this verified chain."""
        claims = verify(
            token,
            "receipt",
            self.authority.public_key,
            self.authority.issuer,
            self.environment_id,
            self.authority.kid,
            historical=True,
        )
        with closing(self.connect()) as db:
            self.read_events(db)
            row = db.execute(
                "SELECT sequence, chain_hash FROM events WHERE token=?", (token,)
            ).fetchone()
        return {
            "signature_valid": True,
            "issuer": claims["iss"],
            "environment": claims["aud"],
            "receipt": claims["body"],
            "in_ledger": row is not None,
            "sequence": row[0] if row else None,
            "chain_hash": row[1] if row else None,
            "actual_action_proven": False,
        }

    def append(
        self,
        db,
        events,
        *,
        request_id,
        payload_hash,
        agent_id,
        mandate_id,
        kind,
        decision,
        reasons,
        amount_minor=0,
        checkpoint=None,
        action=None,
        resource=None,
        tool=None,
        policy=None,
        reference=None,
        reported_status=None,
        reported_by=None,
    ):
        body = ReceiptBody(
            sequence=len(events) + 1,
            previous_hash=events[-1]["hash"] if events else ZERO,
            request_id=request_id,
            payload_hash=payload_hash,
            agent_id=agent_id,
            mandate_id=mandate_id,
            kind=kind,
            decision=decision,
            reasons=reasons,
            amount_minor=amount_minor,
            recorded_at=int(time.time()),
            action=action,
            resource=resource,
            tool=tool,
            policy_id=policy.policy_id if policy else None,
            policy_digest=policy.digest if policy else None,
            checkpoint=checkpoint,
            reference=reference,
            reported_status=reported_status,
            reported_by=reported_by,
        ).model_dump(mode="json", exclude_none=True)
        token = self.authority.issue("receipt", agent_id, self.environment_id, body, ttl=86400)
        link = chain_hash(body["previous_hash"], token)
        db.execute("INSERT INTO events VALUES (?, ?, ?, ?)", (body["sequence"], request_id, token, link))
        return {**body, "hash": link}

    # ------------------------------------------------------------------ decisions
    @staticmethod
    def _history(events, mandate_id, now):
        return [
            PriorEvent(
                decision=e["decision"],
                amount_minor=e["amount_minor"],
                action=e.get("action"),
                tool=e.get("tool"),
                # 0.1 receipts carry no timestamp; count them as recent (conservative).
                recorded_at=e.get("recorded_at", now),
            )
            for e in events
            if e["mandate_id"] == mandate_id and e["kind"] == "simulation"
        ]

    def evaluate(self, passport_token: str, mandate_token: str, request_token: str) -> dict:
        """Verify authority and proof-of-key possession, then ONLY simulate policy/budget.

        Returns {"decision": Decision | None (on idempotent replay), "receipt": dict}.
        """
        pc, passport, mc, mandate = self.credentials(passport_token, mandate_token)
        agent_key = read_public(passport.public_key)
        kid = agent_kid(request_token, agent_key)
        claims = verify(request_token, "request", agent_key, passport.agent_id, self.environment_id, kid)
        request = Request.model_validate(claims["body"])
        if not (
            request.agent_id == passport.agent_id == claims["sub"]
            and request.mandate_id == mc["jti"]
            and request.environment == self.environment_id
        ):
            raise ValueError("Request identity, mandate, or environment mismatch")
        payload_hash = digest(request.model_dump())
        with self.transaction() as db:
            # Verify again inside the transaction: a lock wait must not extend validity.
            self.credentials(passport_token, mandate_token)
            verify(request_token, "request", agent_key, passport.agent_id, self.environment_id, kid)
            events = self.read_events(db)
            existing = next((e for e in events if e["request_id"] == request.request_id), None)
            if existing:
                if existing["payload_hash"] != payload_hash:
                    raise ConflictError("Idempotency key reused for different request")
                return {"decision": None, "receipt": {**existing, "replayed": True}}
            now = int(time.time())
            decision = evaluate(
                policy=self.policy,
                mandate=mandate,
                mandate_id=mc["jti"],
                request=request,
                revoked=self.is_revoked(db, pc["jti"], mc["jti"]),
                history=self._history(events, mc["jti"], now),
                now=now,
            )
            receipt = self.append(
                db,
                events,
                request_id=request.request_id,
                payload_hash=payload_hash,
                agent_id=passport.agent_id,
                mandate_id=mc["jti"],
                kind="simulation",
                decision=decision.decision,
                reasons=decision.reasons,
                amount_minor=request.amount_minor,
                action=request.action,
                resource=request.resource,
                tool=request.tool,
                policy=self.policy,
            )
            return {"decision": decision, "receipt": receipt}

    def simulate(self, passport_token: str, mandate_token: str, request_token: str):
        """0.1-compatible entry point: returns the receipt body plus its chain hash."""
        return self.evaluate(passport_token, mandate_token, request_token)["receipt"]

    def spent(self, mandate_id: str) -> int:
        with closing(self.connect()) as db:
            events = self.read_events(db)
        return sum(
            e["amount_minor"]
            for e in events
            if e["mandate_id"] == mandate_id and e["kind"] == "simulation" and e["decision"] == "allow"
        )

    # ------------------------------------------------------------------ outcomes
    def record_outcome(
        self,
        request_id: str,
        status: str,
        *,
        detail_sha256: str | None = None,
        report_token: str | None = None,
        agent_public_key: str | None = None,
    ) -> dict:
        """Record an executor-reported outcome for an ALLOWED simulation decision.

        A report signed by the agent key ("autheo-outcome+jwt") is marked agent_signed;
        otherwise it is an operator_api claim. Neither proves the action happened.
        """
        with self.transaction() as db:
            events = self.read_events(db)
            decision = next(
                (e for e in events if e["request_id"] == request_id and e["kind"] == "simulation"), None
            )
            if decision is None:
                raise NotFoundError("No decision receipt exists for this request")
            if decision["decision"] != "allow":
                raise ValueError("Outcomes can only be recorded for allowed decisions")
            report = OutcomeReport(
                request_id=request_id,
                agent_id=decision["agent_id"],
                environment=self.environment_id,
                status=status,
                detail_sha256=detail_sha256,
            )
            reported_by = "operator_api"
            if report_token is not None:
                if agent_public_key is None:
                    raise ValueError("Agent public key is required to verify a signed report")
                agent_key = read_public(agent_public_key)
                claims = verify(
                    report_token, "outcome", agent_key, decision["agent_id"], self.environment_id,
                    agent_kid(report_token, agent_key),
                )
                if claims["sub"] != decision["agent_id"] or OutcomeReport.model_validate(claims["body"]) != report:
                    raise ValueError("Signed outcome report does not match")
                reported_by = "agent_signed"
            payload_hash = digest(report.model_dump())
            existing = next((e for e in events if e["request_id"] == "outcome:" + request_id), None)
            if existing:
                if existing["payload_hash"] != payload_hash:
                    raise ConflictError("A different outcome was already recorded for this request")
                return {**existing, "replayed": True}
            return self.append(
                db,
                events,
                request_id="outcome:" + request_id,
                payload_hash=payload_hash,
                agent_id=decision["agent_id"],
                mandate_id=decision["mandate_id"],
                kind="outcome_report",
                decision="recorded",
                reasons=[f"executor_reported_{status}", "not_independently_verified"],
                action=decision.get("action"),
                resource=decision.get("resource"),
                tool=decision.get("tool"),
                reference=request_id,
                reported_status=status,
                reported_by=reported_by,
            )

    # ------------------------------------------------------------------ handoffs
    def prepare_handoff(self, passport_token, mandate_token, destination, scopes, checkpoint: Checkpoint):
        """Operator creates a checkpoint, not a runnable agent or a destination mandate."""
        pc, passport, mc, mandate = self.credentials(passport_token, mandate_token)
        with self.transaction() as db:
            self.credentials(passport_token, mandate_token)
            events = self.read_events(db)
            if self.is_revoked(db, pc["jti"], mc["jti"]):
                raise ValueError("Revoked authority")
            if (
                "environment.handoff" not in mandate.scopes
                or destination not in mandate.destinations
                or destination not in passport.environments
                or destination == self.environment_id
                or not set(scopes).issubset(mandate.scopes)
            ):
                raise ValueError("Handoff scope or destination denied")
            bundle = Handoff(
                agent_id=passport.agent_id,
                owner_id=passport.owner_id,
                source_environment=self.environment_id,
                destination_environment=destination,
                source_mandate_id=mc["jti"],
                passport_digest=digest(passport_token),
                scopes=scopes,
                checkpoint=checkpoint,
                source_audit_head=events[-1]["hash"] if events else ZERO,
            )
            token = self.authority.issue("handoff", passport.agent_id, destination, bundle.model_dump())
            # Record issuance so even a never-imported checkpoint has a source-side receipt.
            token_id = self.owner_document(token, "handoff", destination)["jti"]
            self.append(
                db,
                events,
                request_id="export:" + token_id,
                payload_hash=digest(token),
                agent_id=passport.agent_id,
                mandate_id=mc["jti"],
                kind="handoff_export",
                decision="checkpoint_only",
                reasons=["no_keys_or_budget_transferred"],
                checkpoint=checkpoint.model_dump(),
            )
            return token

    def accept_handoff(self, token, passport_token, source_mandate_token, allowed_scopes):
        claims = self.owner_document(token, "handoff", self.environment_id)
        bundle = Handoff.model_validate(claims["body"])
        pc, passport, mc, mandate = self.credentials(
            passport_token, source_mandate_token, bundle.source_environment
        )
        if not (
            bundle.agent_id == passport.agent_id == claims["sub"]
            and bundle.owner_id == passport.owner_id
            and bundle.source_mandate_id == mc["jti"]
            and bundle.destination_environment == self.environment_id
            and self.environment_id != bundle.source_environment
            and self.environment_id in passport.environments
            and self.environment_id in mandate.destinations
            and bundle.passport_digest == digest(passport_token)
            and "environment.handoff" in mandate.scopes
            and set(bundle.scopes).issubset(mandate.scopes)
            and set(bundle.scopes).issubset(allowed_scopes)
        ):
            raise ValueError("Handoff destination, identity, or policy mismatch")
        with self.transaction() as db:
            self.owner_document(token, "handoff", self.environment_id)
            self.credentials(passport_token, source_mandate_token, bundle.source_environment)
            if self.is_revoked(db, pc["jti"], mc["jti"], claims["jti"]):
                raise ValueError("Revoked handoff authority")
            events = self.read_events(db)
            if any(e["request_id"] == "import:" + claims["jti"] for e in events):
                raise ConflictError("Handoff replay rejected")
            return self.append(
                db,
                events,
                request_id="import:" + claims["jti"],
                payload_hash=digest(token),
                agent_id=passport.agent_id,
                mandate_id=mc["jti"],
                kind="handoff_import",
                decision="checkpoint_only",
                reasons=["fresh_destination_mandate_required", "source_revocation_service_not_integrated"],
                checkpoint=bundle.checkpoint.model_dump(),
            )

    # ------------------------------------------------------------------ exports
    def export_audit(self, output: Path):
        with self.transaction() as db:
            self.read_events(db)
            tokens = [row[0] for row in db.execute("SELECT token FROM events ORDER BY sequence")]
        output.write_text(json.dumps({"receipts": tokens}, indent=2) + "\n", encoding="utf-8")

    def snapshot(self, passport_token, mandate_token):
        pc, passport, mc, mandate = self.credentials(passport_token, mandate_token)
        with self.transaction() as db:
            events = self.read_events(db)
            revoked = self.is_revoked(db, pc["jti"], mc["jti"])
        spent = sum(
            e["amount_minor"]
            for e in events
            if e["mandate_id"] == mc["jti"] and e["kind"] == "simulation" and e["decision"] == "allow"
        )
        own_events = [e for e in events if e["agent_id"] == passport.agent_id]
        public_events = [
            {
                k: e[k]
                for k in (
                    "sequence",
                    "request_id",
                    "kind",
                    "decision",
                    "reasons",
                    "amount_minor",
                    "hash",
                    "previous_hash",
                    "executed",
                )
            }
            for e in own_events[-20:]
        ]
        body = dict(
            version=1,
            mode="simulation_only",
            environment_id=self.environment_id,
            agent_id=passport.agent_id,
            execution_authorized=False,
            passport=dict(
                owner_id=passport.owner_id,
                key_fingerprint=digest(passport.public_key),
                expires_at=pc["exp"],
                ownership="configured_issuer_assertion",
            ),
            mandate=dict(
                id=mc["jti"],
                scopes=mandate.scopes,
                resources=mandate.resources,
                asset="DEMO",
                per_action_minor=mandate.per_action_minor,
                total_budget_minor=mandate.total_budget_minor,
                spent_minor=spent,
                remaining_minor=mandate.total_budget_minor - spent,
                expires_at=mc["exp"],
                revoked=revoked,
            ),
            audit=dict(
                head=events[-1]["hash"] if events else ZERO,
                count=len(events),
                tamper_evident=True,
                immutable=False,
                externally_anchored=False,
            ),
            receipts=public_events,
        )
        ttl = min(120, pc["exp"] - int(time.time()), mc["exp"] - int(time.time()))
        return self.authority.issue("trust-snapshot", passport.agent_id, "autheo-mcp-readonly", body, ttl=ttl)

    def export_snapshot(self, directory: Path, passport_token, mandate_token):
        """No private keys, bearer credentials, checkpoint data, or request payloads are exported."""
        directory.mkdir(parents=True, exist_ok=True)
        token = self.snapshot(passport_token, mandate_token)
        # Atomic replacement avoids readers observing a partial token.
        pending = directory / "trust-snapshot.jwt.tmp"
        pending.write_text(token, encoding="utf-8")
        pending.replace(directory / "trust-snapshot.jwt")
        (directory / "issuer-public.pem").write_text(public_pem(self.authority.public_key), encoding="utf-8")
        config = {
            "AUTHEO_AGENT_TRUST_SNAPSHOT": str((directory / "trust-snapshot.jwt").resolve()),
            "AUTHEO_AGENT_TRUST_PUBLIC_KEY": str((directory / "issuer-public.pem").resolve()),
            "AUTHEO_AGENT_TRUST_ISSUER": self.authority.issuer,
            "AUTHEO_AGENT_TRUST_KEY_ID": self.authority.kid,
            "AUTHEO_AGENT_TRUST_SUBJECT": self.owner_document(
                passport_token, "passport", "autheo-agent-environment"
            )["sub"],
            "AUTHEO_AGENT_TRUST_ENVIRONMENT": self.environment_id,
        }
        (directory / "mcp-environment.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        return config
