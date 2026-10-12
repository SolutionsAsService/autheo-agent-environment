"""Ephemeral, local-only session for the browser-based trust-layer demo.

Since 0.2 the session is a thin wrapper around an ephemeral TrustService: the
browser talks to the same /v1 API that the CLI and integrations use. Keys and
tokens live in a temporary state directory deleted by close().
"""

from __future__ import annotations

import json

from .policy import DEFAULT_POLICY
from .service import ActionInput, EvaluateInput, IdentityIssueInput, MandateGrantInput, TrustService
from .signing import verify


class WebDemoSession:
    """Keep demo keys and bearer tokens server-side; execute no external action."""

    def __init__(self):
        self.environment_id = "env:research"
        self.owner_id = "human:operator-demo"
        # Mandate-only policy keeps the classic allow -> escalate -> block story.
        self.service = TrustService.ephemeral(
            environments=[self.environment_id], policy_text=json.dumps(DEFAULT_POLICY.model_dump(mode="json"))
        )
        identity = self.service.issue_identity(IdentityIssueInput(
            agent_id="agent:research-01", owner_id=self.owner_id, environments=[self.environment_id],
            generate_key=True, ttl_seconds=3600,
        ))
        self.agent_id = identity["agent_id"]
        self.passport_token = identity["passport_token"]
        grant = self.service.grant_mandate(MandateGrantInput(
            agent_id=self.agent_id, environment=self.environment_id,
            scopes=["marketplace.read", "compute.simulate"], resources=["listing:demo-01"],
            per_action_minor=80, total_budget_minor=100, approval_threshold_minor=50,
        ))
        self.mandate_id = grant["mandate_id"]
        self.mandate_token = grant["mandate_token"]
        self.environment = self.service.environment(self.environment_id)
        self.authority = self.service.authority
        self.api_token = self.service.state.api_token

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
                "agent_id": self.agent_id,
                "identifier_type": "local demo identifiers; not DIDs",
                "ownership": snapshot["passport"]["ownership"],
                "expires_at": snapshot["passport"]["expires_at"],
            },
            "mandate": snapshot["mandate"],
            "audit": snapshot["audit"],
            "receipts": snapshot["receipts"],
        }

    def simulate(self, action: str, resource: str, amount_minor: int) -> dict:
        result = self.service.evaluate(EvaluateInput(request=ActionInput(
            agent_id=self.agent_id, mandate_id=self.mandate_id, action=action, resource=resource,
            amount_minor=amount_minor,
        )))
        return result["receipt"]

    def close(self) -> None:
        self.service.close()
