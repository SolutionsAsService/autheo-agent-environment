"""Serve the local-only browser demo on the loopback interface.

The page talks to the same /v1 trust API as the CLI and integrations (mounted on
this server, same origin, bearer token injected into the page). The original
/api/state, /api/simulate and /api/sample routes remain for compatibility.
"""

from __future__ import annotations

import argparse
import html
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from json import JSONDecodeError

from pydantic import ValidationError

from .api import ApiRouter
from .web_demo import WebDemoSession

MAX_BODY_BYTES = 4096
ASSETS = {
    "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/did-demo.js": ("did-demo.js", "text/javascript; charset=utf-8"),
    # Byte-identical copy of interop/js/autheo-did.mjs (enforced by tests/test_webapp.py).
    "/assets/autheo-did.mjs": ("autheo-did.mjs", "text/javascript; charset=utf-8"),
}
MAX_API_BODY_BYTES = 65536
SAMPLE_REQUESTS = [
    {"action": "compute.simulate", "resource": "listing:demo-01", "amount_minor": 40},
    {"action": "compute.simulate", "resource": "listing:demo-01", "amount_minor": 55},
    {"action": "compute.simulate", "resource": "listing:demo-01", "amount_minor": 81},
]


def create_server(port: int = 8765) -> ThreadingHTTPServer:
    session = WebDemoSession()
    csrf_token = session.api_token
    router = ApiRouter(session.service, csrf_token)
    page_values = {
        "__AUTHEO_DEMO_TOKEN__": csrf_token,
        "__AUTHEO_AGENT_ID__": html.escape(session.agent_id),
        "__AUTHEO_MANDATE_ID__": html.escape(session.mandate_id),
        "__AUTHEO_ENVIRONMENT__": html.escape(session.environment_id),
    }
    web_root = files("autheo_agent_environment").joinpath("web")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AutheoLocalDemo/1.0"

        def log_message(self, format_string: str, *args) -> None:
            return

        @property
        def expected_host(self) -> str:
            return f"127.0.0.1:{self.server.server_port}"

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, value: dict) -> None:
            self._send(status, "application/json; charset=utf-8", json.dumps(value).encode())

        def _local_request(self) -> bool:
            host = self.headers.get("Host", "").lower()
            if host != self.expected_host:
                self._json(421, {"error": "local_host_only"})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin != f"http://{self.expected_host}":
                self._json(403, {"error": "same_origin_only"})
                return False
            return True

        def _read_payload(self) -> dict | None:
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self._json(415, {"error": "application_json_required"})
                return None
            try:
                size = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                size = -1
            if not 0 <= size <= MAX_BODY_BYTES:
                self._json(413, {"error": "invalid_body_size"})
                return None
            try:
                payload = json.loads(self.rfile.read(size))
            except (JSONDecodeError, UnicodeDecodeError):
                self._json(400, {"error": "invalid_json"})
                return None
            if not isinstance(payload, dict):
                self._json(400, {"error": "json_object_required"})
                return None
            return payload

        def _require_demo_token(self) -> bool:
            if not secrets.compare_digest(self.headers.get("X-Autheo-Demo-Token", ""), csrf_token):
                self._json(403, {"error": "demo_token_required"})
                return False
            return True

        def _api(self, method: str) -> None:
            body = b""
            if method == "POST":
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    size = -1
                body = self.rfile.read(size) if 0 <= size <= MAX_API_BODY_BYTES else None
            status, payload = router.handle(method, self.path, self.headers, body)
            self._json(status, payload)

        def do_GET(self) -> None:
            if not self._local_request():
                return
            if self.path.startswith("/v1/"):
                self._api("GET")
                return
            if self.path == "/":
                body = web_root.joinpath("index.html").read_text(encoding="utf-8")
                for marker, value in page_values.items():
                    body = body.replace(marker, value)
                self._send(200, "text/html; charset=utf-8", body.encode())
                return
            if self.path == "/api/state":
                self._json(200, session.state())
                return
            if self.path in ASSETS:
                name, content_type = ASSETS[self.path]
                self._send(200, content_type, web_root.joinpath(name).read_bytes())
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if not self._local_request():
                return
            if self.path.startswith("/v1/"):
                self._api("POST")
                return
            if not self._require_demo_token():
                return
            payload = self._read_payload()
            if payload is None:
                return
            if self.path == "/api/simulate":
                results = [self._simulate_one(payload)]
            elif self.path == "/api/sample":
                if payload:
                    self._json(400, {"error": "sample_route_accepts_no_fields"})
                    return
                results = [self._simulate_one(sample) for sample in SAMPLE_REQUESTS]
            else:
                self._json(404, {"error": "not_found"})
                return
            if any(result is None for result in results):
                return
            self._json(200, {"results": results, "state": session.state()})

        def _simulate_one(self, payload: dict) -> dict | None:
            if set(payload) != {"action", "resource", "amount_minor"}:
                self._json(400, {"error": "exactly_action_resource_amount_required"})
                return None
            try:
                result = session.simulate(
                    payload["action"], payload["resource"], payload["amount_minor"]
                )
            except (ValidationError, ValueError, TypeError):
                self._json(400, {"error": "request_failed_schema_validation"})
                return None
            return {
                "decision": result["decision"],
                "reasons": result["reasons"],
                "request_id": result["request_id"],
                "sequence": result["sequence"],
                "amount_minor": result["amount_minor"],
                "executed": result["executed"],
                "receipt_hash": result["hash"],
            }

    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError:
        session.close()
        raise
    server.daemon_threads = True
    server.demo_session = session
    server.demo_token = csrf_token
    return server


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    server = create_server(args.port)
    print(f"Autheo Agent Trust LOCAL DEMO: http://127.0.0.1:{server.server_port}/")
    print("Loopback only. All decisions are simulated; no external actions execute.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        server.demo_session.close()


if __name__ == "__main__":
    main()
