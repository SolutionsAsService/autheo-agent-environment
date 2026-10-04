"""Ephemeral, local-only session for the browser-based trust-layer demo."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from .environment import Environment
from .models import Mandate, Passport, Request
from .signing import Signer, public_pem, verify


class WebDemoSession:
    """Keep demo keys and bearer tokens in process memory; execute no external action."""

    def __init__(self):
        self._temporary = TemporaryDirectory(prefix="autheo-agent-web-demo-")
        self.authority = Signer.generate("autheo-demo-authority")
        self.agent = Signer.generate("agent:research-01")
        self.environment_id = "env:research"
        self.owner_id = "human:operator-demo"
        self.passport = Passport(
            agent_id=self.agent.issuer,
            owner_id=self.owner_id,
            public_key=public_pem(self.agent.public_key),
            environments=[self.environment_id],
        )
        self.passport_token = self.authority.issue(
            "passport",
            self.agent.issuer,
            "autheo-agent-environment",
            self.passport.model_dump(),
            ttl=3600,
        )
        self.mandate = Mandate(
            agent_id=self.agent.issuer,
            owner_id=self.owner_id,
            environment=self.environment_id,
            scopes=["marketplace.read", "compute.simulate"],
            resources=["listing:demo-01"],
            per_action_minor=80,
            total_budget_minor=100,
            approval_threshold_minor=50,
        )
        self.mandate_token = self.authority.issue(
            "mandate",
            self.agent.issuer,
            self.environment_id,
            self.mandate.model_dump(),
            ttl=3600,
        )
        database = Path(self._temporary.name) / "demo.db"
        self.environment = Environment(database, self.environment_id, self.authority)
        self.mandate_id = self.environment.owner_document(
            self.mandate_token, "mandate", self.environment_id
        )["jti"]

    def state(self) -> dict:
        token = self.environment.snapshot(self.passport_token, self.mandate_token)
        claims = verify(
            token,
            "trust-snapshot",
            self.authority.public_key,
            self.authority.issuer,
            "autheo-mcp-readonly",
            self.authority.kid,
        )
        snapshot = claims["body"]
        return {
            "mode": "LOCAL DEMO",
            "execution_authorized": False,
            "identity": {
                "owner_id": self.owner_id,
                "agent_id": self.agent.issuer,
                "identifier_type": "local demo identifiers; not DIDs",
                "ownership": snapshot["passport"]["ownership"],
                "expires_at": snapshot["passport"]["expires_at"],
            },
            "mandate": snapshot["mandate"],
            "audit": snapshot["audit"],
            "receipts": snapshot["receipts"],
        }

    def simulate(self, action: str, resource: str, amount_minor: int) -> dict:
        request = Request(
            request_id=f"web:{uuid4()}",
            agent_id=self.agent.issuer,
            environment=self.environment_id,
            mandate_id=self.mandate_id,
            action=action,
            resource=resource,
            amount_minor=amount_minor,
        )
        signed_request = self.agent.issue(
            "request", self.agent.issuer, self.environment_id, request.model_dump()
        )
        return self.environment.simulate(self.passport_token, self.mandate_token, signed_request)

    def close(self) -> None:
        self._temporary.cleanup()
