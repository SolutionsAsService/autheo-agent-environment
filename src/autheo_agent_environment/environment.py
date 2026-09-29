"""Single-host reference control plane. All actions and balances are simulations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path

from .models import Checkpoint, Handoff, Mandate, Passport, Request
from .signing import Signer, digest, public_pem, read_public, verify

ZERO = "0" * 64


class Environment:
    def __init__(self, path: Path, environment_id: str, authority: Signer):
        self.path, self.environment_id, self.authority = Path(path), environment_id, authority
        with closing(self.connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    token TEXT NOT NULL, chain_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS revoked (jti TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            expected = {
                "environment": environment_id,
                "issuer": authority.issuer,
                "key": digest(public_pem(authority.public_key)),
            }
            current = dict(db.execute("SELECT name, value FROM metadata"))
            if current and current != expected:
                raise ValueError("Database belongs to a different environment or signing identity")
            db.executemany("INSERT OR IGNORE INTO metadata VALUES (?, ?)", expected.items())

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

    def revoke(self, jti: str):
        """Trusted local operator operation, not exposed to agents or MCP."""
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (jti,))

    @staticmethod
    def is_revoked(db, *ids):
        return any(db.execute("SELECT 1 FROM revoked WHERE jti=?", (jti,)).fetchone() for jti in ids)

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

    def read_events(self, db):
        previous, events = ZERO, []
        for sequence, request_id, token, chain_hash in db.execute("SELECT * FROM events ORDER BY sequence"):
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
            expected = hashlib.sha256((previous + token).encode()).hexdigest()
            if (
                sequence != len(events) + 1
                or body.get("sequence") != sequence
                or body.get("previous_hash") != previous
                or body.get("request_id") != request_id
                or expected != chain_hash
                or body.get("executed") is not False
            ):
                raise ValueError("Audit chain integrity failure")
            events.append({**body, "hash": chain_hash})
            previous = chain_hash
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
    ):
        body = dict(
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
            executed=False,
            simulation_only=True,
        )
        if checkpoint is not None:
            body["checkpoint"] = checkpoint
        token = self.authority.issue("receipt", agent_id, self.environment_id, body, ttl=86400)
        chain_hash = hashlib.sha256((body["previous_hash"] + token).encode()).hexdigest()
        db.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?)", (body["sequence"], request_id, token, chain_hash)
        )
        return {**body, "hash": chain_hash}

    def simulate(self, passport_token: str, mandate_token: str, request_token: str):
        """Verify authority and proof-of-key possession, then ONLY simulate policy/budget."""
        pc, passport, mc, mandate = self.credentials(passport_token, mandate_token)
        claims = verify(
            request_token, "request", read_public(passport.public_key), passport.agent_id, self.environment_id
        )
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
            verify(
                request_token,
                "request",
                read_public(passport.public_key),
                passport.agent_id,
                self.environment_id,
            )
            events = self.read_events(db)
            existing = next((e for e in events if e["request_id"] == request.request_id), None)
            if existing:
                if existing["payload_hash"] != payload_hash:
                    raise ValueError("Idempotency key reused for different request")
                return {**existing, "replayed": True}
            spent = sum(
                e["amount_minor"]
                for e in events
                if e["mandate_id"] == mc["jti"] and e["decision"] == "allow" and e["kind"] == "simulation"
            )
            reasons = []
            if self.is_revoked(db, pc["jti"], mc["jti"]):
                reasons.append("revoked")
            if request.action not in mandate.scopes:
                reasons.append("scope_denied")
            if request.resource not in mandate.resources:
                reasons.append("resource_denied")
            if request.amount_minor > mandate.per_action_minor:
                reasons.append("per_action_limit")
            if spent + request.amount_minor > mandate.total_budget_minor:
                reasons.append("total_budget_limit")
            decision = (
                "block"
                if reasons
                else "escalate"
                if request.amount_minor > mandate.approval_threshold_minor
                else "allow"
            )
            if decision == "escalate":
                reasons = ["human_review_required"]
            if decision == "allow":
                reasons = ["within_demo_policy"]
            return self.append(
                db,
                events,
                request_id=request.request_id,
                payload_hash=payload_hash,
                agent_id=passport.agent_id,
                mandate_id=mc["jti"],
                kind="simulation",
                decision=decision,
                reasons=reasons,
                amount_minor=request.amount_minor,
            )

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
                raise ValueError("Handoff replay rejected")
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
