"""Loopback-only local HTTP API for the trust service (stdlib server, bearer-token auth).

Security posture (local reference, not a hosted service):
* binds 127.0.0.1 by default and refuses non-loopback addresses unless
  --allow-remote is given explicitly (there is no TLS; do not expose it);
* every /v1 route except health, openapi and schemas requires
  "Authorization: Bearer <token>" compared in constant time;
* Host must be a loopback name with the bound port (DNS-rebinding defence) and
  any Origin header must be same-origin; no CORS headers are ever sent;
* JSON bodies only, at most 64 KiB, validated by strict models (unknown fields fail).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import secrets
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from json import JSONDecodeError
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import jwt
from pydantic import BaseModel, ValidationError

from . import __version__
from .data_integrity import ProofError
from .did import DidError
from .errors import ConflictError, NotFoundError
from .schemas import SCHEMAS, SCHEMAS_V2, build_schema
from .service import (
    CheckpointInput,
    EvaluateInput,
    HandoffAcceptInput,
    IdentityIssueInput,
    LedgerVerifyInput,
    MandateGrantInput,
    OutcomeInput,
    RevokeInput,
    TrustService,
    VerifyReceiptInput,
)
from .service_did import (
    BundleVerifyInput,
    ChainVerifyInput,
    DelegateInput,
    DidCreateInput,
    InvocationEvaluateInput,
    RevocationInput,
    TrustRootInput,
)

MAX_BODY_BYTES = 65536
DEFAULT_PORT = 8780


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str | None = None):
        super().__init__(code)
        self.status, self.code, self.detail = status, code, detail


def _validate(model: type[BaseModel], payload) -> BaseModel:
    try:
        return model.model_validate(payload)
    except ValidationError as error:
        fields = sorted({".".join(str(p) for p in item["loc"]) for item in error.errors()})
        raise ApiError(400, "schema_validation_failed", ", ".join(fields)[:300]) from error


def _limit(query: dict) -> int:
    try:
        value = int(query.get("limit", ["50"])[0])
    except ValueError as error:
        raise ApiError(400, "invalid_limit") from error
    if not 1 <= value <= 500:
        raise ApiError(400, "invalid_limit")
    return value


class ApiRouter:
    """Transport-independent router. Host/Origin checks belong to the HTTP layer."""

    def __init__(self, service: TrustService, token: str):
        if len(token) < 16:
            raise ValueError("API token is too short")
        self.service, self.token = service, token

    def authorized(self, headers) -> bool:
        value = headers.get("Authorization", "")
        scheme, _, supplied = value.partition(" ")
        return scheme.lower() == "bearer" and secrets.compare_digest(supplied.strip(), self.token)

    def handle(self, method: str, target: str, headers, body: bytes | None) -> tuple[int, dict]:
        try:
            return 200, self._dispatch(method, target, headers, body)
        except ApiError as error:
            payload = {"error": error.code}
            if error.detail:
                payload["detail"] = error.detail
            return error.status, payload
        except NotFoundError as error:
            return 404, {"error": "not_found", "detail": str(error)[:300]}
        except ConflictError as error:
            return 409, {"error": "conflict", "detail": str(error)[:300]}
        except ValidationError:
            return 400, {"error": "schema_validation_failed"}
        except ProofError as error:
            payload = {"error": "proof_invalid", "code": error.code, "detail": str(error)[:300]}
            if getattr(error, "errors", None):
                payload["errors"] = error.errors[:20]
            return 400, payload
        except DidError as error:
            return 400, {"error": "did_invalid", "code": error.code, "detail": str(error)[:300]}
        except jwt.InvalidSignatureError:
            return 400, {"error": "signature_invalid"}
        except jwt.ExpiredSignatureError:
            return 400, {"error": "token_expired"}
        except jwt.InvalidTokenError as error:
            return 400, {"error": "token_invalid", "detail": type(error).__name__}
        except ValueError as error:
            return 400, {"error": "rejected", "detail": str(error)[:300]}

    def _body(self, headers, body: bytes | None) -> dict:
        if headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ApiError(415, "application_json_required")
        if body is None:
            raise ApiError(413, "invalid_body_size")
        try:
            payload = json.loads(body or b"{}")
        except (JSONDecodeError, UnicodeDecodeError) as error:
            raise ApiError(400, "invalid_json") from error
        if not isinstance(payload, dict):
            raise ApiError(400, "json_object_required")
        return payload

    def _dispatch(self, method: str, target: str, headers, body: bytes | None) -> dict:
        parts = urlsplit(target)
        path, query = parts.path.rstrip("/") or "/", parse_qs(parts.query)
        segments = [unquote(s) for s in path.split("/")[1:]]
        if path == "/v1/health" and method == "GET":
            return {"status": "ok", "version": __version__, "mode": "local_reference", "executes_actions": False}
        if path == "/v1/openapi.json" and method == "GET":
            from .openapi import build_openapi

            return build_openapi()
        if path == "/v1/schemas" and method == "GET":
            return {"schemas": {name: f"/v1/schemas/{name}" for name in SCHEMAS},
                    "schemas_v2": {name: f"/v1/schemas/v2/{name}" for name in SCHEMAS_V2}}
        if len(segments) == 4 and segments[:3] == ["v1", "schemas", "v2"] and method == "GET":
            if segments[3] not in SCHEMAS_V2:
                raise ApiError(404, "not_found")
            return build_schema(segments[3], 2)
        if len(segments) == 3 and segments[:2] == ["v1", "schemas"] and method == "GET":
            if segments[2] not in SCHEMAS:
                raise ApiError(404, "not_found")
            return build_schema(segments[2])
        if not path.startswith("/v1/"):
            raise ApiError(404, "not_found")
        if not self.authorized(headers):
            raise ApiError(401, "bearer_token_required")
        service = self.service

        if method == "GET":
            if path == "/v1/info":
                return service.info()
            if path == "/v1/policy":
                return service.policy_document()
            if len(segments) == 3 and segments[1] == "identities":
                return service.get_identity(segments[2])
            if len(segments) == 3 and segments[1] == "mandates":
                return service.mandate_status(segments[2])
            if path == "/v1/ledger/receipts":
                environment = query.get("environment", [""])[0]
                agent = query.get("agent_id", [None])[0]
                return service.receipts(environment, _limit(query), agent)
            if path == "/v1/dids":
                return service.list_dids()
            if len(segments) == 3 and segments[1] == "dids":
                return service.resolve_did(segments[2])
            if path == "/v1/revocations":
                return service.revocation_list(query.get("environment", [""])[0])
            if path == "/v1/ledger/v2":
                return service.v2_ledger(query.get("environment", [""])[0])
            if path == "/v1/ledger/verify":
                payload = {"environment": query.get("environment", [""])[0]}
                if "expected_head" in query:
                    payload["expected_head"] = query["expected_head"][0]
                return service.verify_ledger(_validate(LedgerVerifyInput, payload))
            raise ApiError(404, "not_found")

        if method != "POST":
            raise ApiError(405, "method_not_allowed")
        payload = self._body(headers, body)
        if path == "/v1/identities":
            return service.issue_identity(_validate(IdentityIssueInput, payload))
        if len(segments) == 4 and segments[1] == "identities" and segments[3] == "revoke":
            return service.revoke_identity(segments[2], _validate(RevokeInput, payload))
        if path == "/v1/mandates":
            return service.grant_mandate(_validate(MandateGrantInput, payload))
        if len(segments) == 4 and segments[1] == "mandates" and segments[3] == "revoke":
            return service.revoke_mandate(segments[2], _validate(RevokeInput, payload))
        if path == "/v1/evaluate":
            return service.evaluate(_validate(EvaluateInput, payload))
        if path == "/v1/receipts/outcome":
            return service.record_outcome(_validate(OutcomeInput, payload))
        if path == "/v1/receipts/verify":
            return service.verify_receipt(_validate(VerifyReceiptInput, payload))
        if path == "/v1/ledger/verify":
            return service.verify_ledger(_validate(LedgerVerifyInput, payload))
        if path == "/v1/checkpoints":
            return service.checkpoint(_validate(CheckpointInput, payload))
        if path == "/v1/handoffs/accept":
            return service.accept_handoff(_validate(HandoffAcceptInput, payload))
        if path == "/v1/dids":
            return service.create_did(_validate(DidCreateInput, payload))
        if path == "/v1/trust-roots":
            return service.set_trusted_root(_validate(TrustRootInput, payload))
        if path == "/v1/delegations":
            return service.delegate(_validate(DelegateInput, payload))
        if path == "/v1/delegations/verify":
            return service.verify_delegation_chain(_validate(ChainVerifyInput, payload))
        if path == "/v1/revocations":
            return service.revoke_delegation(_validate(RevocationInput, payload))
        if path == "/v1/invocations/evaluate":
            return service.evaluate_invocation(_validate(InvocationEvaluateInput, payload))
        if path == "/v1/bundles/verify":
            return service.verify_bundle(_validate(BundleVerifyInput, payload))
        raise ApiError(404, "not_found")


SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def allowed_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def create_api_server(
    service: TrustService,
    token: str,
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    allow_remote: bool = False,
) -> ThreadingHTTPServer:
    if not is_loopback(host) and not allow_remote:
        raise ValueError("Refusing to bind a non-loopback address without allow_remote")
    router = ApiRouter(service, token)

    class Handler(BaseHTTPRequestHandler):
        server_version = f"AutheoLocalTrustAPI/{__version__}"

        def log_message(self, format_string: str, *args) -> None:
            return

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _guard(self) -> bool:
            if not allow_remote:
                host_header = self.headers.get("Host", "").lower()
                if host_header not in allowed_hosts(self.server.server_port):
                    self._send(421, {"error": "loopback_host_required"})
                    return False
            origin = self.headers.get("Origin")
            if origin is not None and origin.lower() != f"http://{self.headers.get('Host', '').lower()}":
                self._send(403, {"error": "same_origin_only"})
                return False
            return True

        def _handle(self, method: str) -> None:
            if not self._guard():
                return
            body = b""
            if method == "POST":
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    size = -1
                body = self.rfile.read(size) if 0 <= size <= MAX_BODY_BYTES else None
            status, payload = router.handle(method, self.path, self.headers, body)
            self._send(status, payload)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

    server_class = _IPv6Server if ":" in host else ThreadingHTTPServer
    server = server_class((host, port), Handler)
    server.daemon_threads = True
    server.router = router
    return server


def serve(state_dir: Path, host: str, port: int, allow_remote: bool = False) -> None:
    from .state import StateDir

    service = TrustService(StateDir(state_dir))
    server = create_api_server(service, service.state.api_token, host, port, allow_remote)
    shown = f"[{host}]" if ":" in host else host
    print(f"Autheo local trust API (reference, simulation only): http://{shown}:{server.server_port}/v1/health")
    print(f"Bearer token file: {service.state.root / 'api-token'}  OpenAPI: /v1/openapi.json")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path(".autheo-state"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--allow-remote", action="store_true")
    args = parser.parse_args(argv)
    serve(args.state_dir, args.host, args.port, args.allow_remote)


if __name__ == "__main__":
    main()
