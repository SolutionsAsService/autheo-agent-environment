"""Run a local-only, ephemeral-key walkthrough. There are no network calls."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .environment import Environment
from .models import Checkpoint, Mandate, Passport, Request
from .signing import Signer, digest, public_pem


def run(output: Path):
    authority = Signer.generate("autheo-demo-authority")
    agent = Signer.generate("agent:research-01")
    passport = Passport(
        agent_id=agent.issuer,
        owner_id="human:operator",
        public_key=public_pem(agent.public_key),
        environments=["env:research", "env:review"],
    )
    passport_token = authority.issue(
        "passport", agent.issuer, "autheo-agent-environment", passport.model_dump(), ttl=3600
    )
    mandate = Mandate(
        agent_id=agent.issuer,
        owner_id=passport.owner_id,
        environment="env:research",
        scopes=["marketplace.read", "compute.simulate", "environment.handoff"],
        resources=["listing:demo-01"],
        destinations=["env:review"],
        per_action_minor=80,
        total_budget_minor=100,
        approval_threshold_minor=50,
    )
    mandate_token = authority.issue("mandate", agent.issuer, "env:research", mandate.model_dump(), ttl=3600)
    with TemporaryDirectory(prefix="autheo-agent-demo-") as temporary:
        source = Environment(Path(temporary) / "source.db", "env:research", authority)
        destination = Environment(Path(temporary) / "destination.db", "env:review", authority)
        mandate_id = source.owner_document(mandate_token, "mandate", "env:research")["jti"]
        receipts = []
        for request_id, amount in [("request:allow", 40), ("request:escalate", 51), ("request:block", 101)]:
            request = Request(
                request_id=request_id,
                agent_id=agent.issuer,
                environment="env:research",
                mandate_id=mandate_id,
                action="compute.simulate",
                resource="listing:demo-01",
                amount_minor=amount,
            )
            signed_request = agent.issue("request", agent.issuer, "env:research", request.model_dump())
            receipts.append(source.simulate(passport_token, mandate_token, signed_request))
        checkpoint = Checkpoint(
            task_id="task:inspect-supply", step="awaiting_review", artifact_sha256=digest({"demo": True})
        )
        handoff = source.prepare_handoff(
            passport_token, mandate_token, "env:review", ["marketplace.read"], checkpoint
        )
        imported = destination.accept_handoff(handoff, passport_token, mandate_token, ["marketplace.read"])
        config = source.export_snapshot(output, passport_token, mandate_token)
        source.export_audit(output / "source-audit.json")
        destination.export_audit(output / "destination-audit.json")
        result = {
            "prototype": True,
            "scope": "local simulations only; no real wallet or live runtime migration",
            "decisions": [receipt["decision"] for receipt in receipts],
            "receipts": receipts,
            "handoff": imported,
            "source_audit": source.audit(),
            "destination_audit": destination.audit(),
            "snapshot_valid_seconds": 120,
            "mcp_environment": config,
        }
        (output / "demo-report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("demo-output"))
    args = parser.parse_args()
    print(json.dumps(run(args.output), indent=2))


if __name__ == "__main__":
    main()
