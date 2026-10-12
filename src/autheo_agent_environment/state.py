"""Local state directory for the persistent mode (CLI and HTTP API).

Layout (created with 0700/0600 permissions where the OS supports them)::

    <state-dir>/
      config.json            issuer id, key id, environments, policy file name
      issuer-key.pem         LOCAL DEVELOPMENT issuer signing key (unencrypted PKCS#8)
      issuer-public.pem      public verification key / trust anchor
      api-token              bearer token for the loopback HTTP API
      policy.yaml            declarative policy (autheo.policy/v1)
      registry.db            mutable operational index: passports, mandates
      ledger-<env>.db        append-only, hash-chained signed receipts per environment
      agents/<agent>.pem     optional server-held agent keys (local-dev custody only)

This is NOT production key custody: keys are files readable by the local user.
Production must use an isolated signer/KMS/HSM (see docs/THREAT-MODEL.md).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .policy import DEFAULT_POLICY, PolicyDocument, load_policy
from .signing import Signer, key_fingerprint, private_pem, public_pem, read_private

STATE_VERSION = 1
DEFAULT_ENVIRONMENTS = ["env:research", "env:review"]
DEFAULT_ISSUER = "autheo-local-authority"
ENV_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,95}$")

DEFAULT_POLICY_YAML = """# Autheo declarative policy (autheo.policy/v1). Operator configuration, never agent input.
# A policy can only NARROW what a signed mandate grants. Outcome precedence:
# block > escalate > allow. See docs/POLICY.md for every field.
schema_version: autheo.policy/v1
policy_id: policy:local-default
description: Mandate limits plus conservative local defaults.
tools:
  allow: []          # empty = only the mandate's exact tool list applies
  deny:
    - "shell.*"      # example: never allow arbitrary shell tools, even if a mandate lists them
budgets: []
rate_limits:
  - id: burst
    max_requests: 60
    window_seconds: 60
time_windows: []
escalations: []
use_mandate_approval_threshold: true
"""


def _private_write(path: Path, text: str) -> None:
    """Create/replace a file readable only by the current user (best effort on Windows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".tmp")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(pending, path)


def safe_name(identifier: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", identifier)


class StateDir:
    def __init__(self, root: Path):
        self.root = Path(root)
        config_path = self.root / "config.json"
        if not config_path.is_file():
            raise FileNotFoundError(
                f"No Autheo state at {self.root}; run: python -m autheo_agent_environment init"
            )
        self.config = json.loads(config_path.read_text(encoding="utf-8"))
        if self.config.get("state_version") != STATE_VERSION:
            raise ValueError("Unsupported state directory version")
        key = read_private((self.root / "issuer-key.pem").read_text(encoding="utf-8"))
        self.authority = Signer(self.config["issuer"], key, self.config["kid"])
        self._temporary = None
        self._init_registry()

    # ------------------------------------------------------------------ creation
    @classmethod
    def init(
        cls,
        root: Path,
        issuer: str = DEFAULT_ISSUER,
        environments: list[str] | None = None,
        policy_text: str | None = None,
    ) -> StateDir:
        root = Path(root)
        if (root / "config.json").exists():
            raise FileExistsError(f"State already initialised at {root}")
        environments = list(environments or DEFAULT_ENVIRONMENTS)
        if not environments or any(not ENV_ID.match(e) for e in environments) or not ENV_ID.match(issuer):
            raise ValueError("Invalid issuer or environment identifier")
        root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(root, 0o700)
        except OSError:  # pragma: no cover - platform dependent
            pass
        key = Ed25519PrivateKey.generate()
        kid = "local-" + key_fingerprint(key.public_key()).split(":", 1)[1][:16]
        _private_write(root / "issuer-key.pem", private_pem(key))
        (root / "issuer-public.pem").write_text(public_pem(key.public_key()), encoding="utf-8")
        _private_write(root / "api-token", secrets.token_urlsafe(32) + "\n")
        (root / "policy.yaml").write_text(policy_text or DEFAULT_POLICY_YAML, encoding="utf-8")
        config = {
            "state_version": STATE_VERSION,
            "issuer": issuer,
            "kid": kid,
            "environments": environments,
            "policy_file": "policy.yaml",
            "created_at": int(time.time()),
            "custody": "local_development_file_key",
        }
        (root / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        state = cls(root)
        state.policy()  # validate the policy file eagerly
        return state

    @classmethod
    def ephemeral(cls, environments: list[str] | None = None, policy_text: str | None = None) -> StateDir:
        temporary = TemporaryDirectory(prefix="autheo-agent-state-")
        state = cls.init(Path(temporary.name) / "state", environments=environments, policy_text=policy_text)
        state._temporary = temporary
        return state

    def close(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    # ------------------------------------------------------------------ accessors
    @property
    def environments(self) -> list[str]:
        return list(self.config["environments"])

    @property
    def api_token(self) -> str:
        return (self.root / "api-token").read_text(encoding="utf-8").strip()

    @property
    def public_key_path(self) -> Path:
        return self.root / "issuer-public.pem"

    def policy(self) -> PolicyDocument:
        name = self.config.get("policy_file")
        if not name:
            return DEFAULT_POLICY
        path = self.root / name
        return load_policy(path) if path.exists() else DEFAULT_POLICY

    def ledger_path(self, environment: str) -> Path:
        return self.root / f"ledger-{safe_name(environment)}.db"

    # ------------------------------------------------------------------ agent keys (dev custody)
    def store_agent_key(self, agent_id: str, key: Ed25519PrivateKey) -> None:
        _private_write(self.root / "agents" / f"{safe_name(agent_id)}.pem", private_pem(key))

    def agent_signer(self, agent_id: str) -> Signer | None:
        path = self.root / "agents" / f"{safe_name(agent_id)}.pem"
        if not path.is_file():
            return None
        return Signer.for_agent(agent_id, read_private(path.read_text(encoding="utf-8")))

    # ------------------------------------------------------------------ registry
    def connect_registry(self):
        return sqlite3.connect(self.root / "registry.db", timeout=10, isolation_level=None)

    def _init_registry(self) -> None:
        with closing(self.connect_registry()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS identities (
                    agent_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, passport_id TEXT NOT NULL,
                    passport_token TEXT NOT NULL, public_key TEXT NOT NULL, custody TEXT NOT NULL,
                    expires_at INTEGER NOT NULL, issued_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS mandates (
                    mandate_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, environment TEXT NOT NULL,
                    mandate_token TEXT NOT NULL, expires_at INTEGER NOT NULL, granted_at INTEGER NOT NULL);
            """)

    def put_identity(self, row: dict) -> None:
        with closing(self.connect_registry()) as db:
            db.execute(
                "INSERT OR REPLACE INTO identities VALUES (:agent_id, :owner_id, :passport_id, "
                ":passport_token, :public_key, :custody, :expires_at, :issued_at)",
                row,
            )

    def get_identity(self, agent_id: str) -> dict | None:
        with closing(self.connect_registry()) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM identities WHERE agent_id=?", (agent_id,)).fetchone()
        return dict(row) if row else None

    def put_mandate(self, row: dict) -> None:
        with closing(self.connect_registry()) as db:
            db.execute(
                "INSERT INTO mandates VALUES (:mandate_id, :agent_id, :environment, :mandate_token, "
                ":expires_at, :granted_at)",
                row,
            )

    def get_mandate(self, mandate_id: str) -> dict | None:
        with closing(self.connect_registry()) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM mandates WHERE mandate_id=?", (mandate_id,)).fetchone()
        return dict(row) if row else None

    def list_mandates(self, agent_id: str | None = None) -> list[dict]:
        with closing(self.connect_registry()) as db:
            db.row_factory = sqlite3.Row
            if agent_id is None:
                rows = db.execute("SELECT * FROM mandates ORDER BY granted_at").fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM mandates WHERE agent_id=? ORDER BY granted_at", (agent_id,)
                ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------ v2: DIDs and trusted roots
    def _write_config(self) -> None:
        pending = self.root / "config.json.tmp"
        pending.write_text(json.dumps(self.config, indent=2) + "\n", encoding="utf-8")
        os.replace(pending, self.root / "config.json")

    def trusted_roots(self, environment: str) -> list[str]:
        """Root DIDs whose delegation chains this environment accepts (operator configuration)."""
        return list(self.config.get("trusted_roots", {}).get(environment, []))

    def set_trusted_root(self, environment: str, did: str, trusted: bool = True) -> list[str]:
        if environment not in self.environments:
            raise ValueError(f"Environment {environment!r} is not configured")
        roots = self.config.setdefault("trusted_roots", {}).setdefault(environment, [])
        if trusted and did not in roots:
            roots.append(did)
        elif not trusted and did in roots:
            roots.remove(did)
        self._write_config()
        return list(roots)

    @property
    def did_web_cache(self) -> Path:
        return self.root / "did-web-cache"

    @property
    def did_web_network(self) -> bool:
        """did:web network resolution is OFF unless the operator sets "did_web_network": true."""
        return self.config.get("did_web_network") is True

    def _did_path(self, did: str) -> Path:
        import hashlib

        return self.root / "dids" / (hashlib.sha256(did.encode()).hexdigest()[:40] + ".json")

    def store_did_key(self, key) -> None:
        """Local-dev custody of a did:key private key (the demo/API convenience path)."""
        _private_write(self._did_path(key.did), json.dumps(key.to_file_json(), indent=2) + "\n")

    def did_key(self, did: str):
        from .did import DidKey

        path = self._did_path(did)
        return DidKey.load(path) if path.is_file() else None

    def list_dids(self) -> list[str]:
        directory = self.root / "dids"
        if not directory.is_dir():
            return []
        return sorted(json.loads(p.read_text(encoding="utf-8"))["did"] for p in directory.glob("*.json"))
