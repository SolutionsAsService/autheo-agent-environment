from __future__ import annotations

import json
import threading
from http.client import HTTPConnection

import pytest
from pydantic import ValidationError

from autheo_agent_environment.web_demo import WebDemoSession
from autheo_agent_environment.webapp import create_server


@pytest.fixture
def running_server():
    server = create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    server.demo_session.close()
    thread.join(timeout=2)


def post(server, path, payload, *, token=None, origin=None, content_type="application/json", host=None):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["X-Autheo-Demo-Token"] = token
    if origin is not None:
        headers["Origin"] = origin
    if host is not None:
        headers["Host"] = host
    body = json.dumps(payload) if payload is not None else ""
    connection.request("POST", path, body=body, headers=headers)
    response = connection.getresponse()
    result = response.status, response.headers, response.read()
    connection.close()
    return result


def test_web_demo_session_uses_simulator_and_never_executes():
    session = WebDemoSession()
    try:
        allow = session.simulate("compute.simulate", "listing:demo-01", 40)
        review = session.simulate("compute.simulate", "listing:demo-01", 55)
        block = session.simulate("compute.simulate", "listing:demo-01", 81)
        state = session.state()

        assert [allow["decision"], review["decision"], block["decision"]] == [
            "allow",
            "escalate",
            "block",
        ]
        assert all(result["executed"] is False for result in (allow, review, block))
        assert state["execution_authorized"] is False
        assert state["identity"]["identifier_type"] == "local demo identifiers; not DIDs"
        assert state["mandate"]["spent_minor"] == 40
        assert state["audit"]["count"] == 3
    finally:
        session.close()


def test_web_demo_rejects_untyped_action_and_records_nothing():
    session = WebDemoSession()
    try:
        with pytest.raises(ValidationError):
            session.simulate("arbitrary.execute", "listing:demo-01", 1)
        assert session.state()["audit"]["count"] == 0
    finally:
        session.close()


def test_local_page_and_state_do_not_export_credentials(running_server):
    server = running_server
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    connection.request("GET", "/")
    page = connection.getresponse()
    html = page.read().decode()
    assert page.status == 200
    assert "LOCAL DEMO" in html
    assert "__AUTHEO_DEMO_TOKEN__" not in html
    assert "Content-Security-Policy" in page.headers
    connection.close()

    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    connection.request("GET", "/api/state")
    response = connection.getresponse()
    state = json.loads(response.read())
    assert response.status == 200
    assert state["execution_authorized"] is False
    assert "passport_token" not in state and "mandate_token" not in state
    assert "PRIVATE KEY" not in json.dumps(state)
    connection.close()


def test_browser_assets_are_served_from_the_local_app(running_server):
    connection = HTTPConnection("127.0.0.1", running_server.server_port, timeout=3)
    for path, expected_type, marker in [
        ("/assets/app.css", "text/css", ".trust-flow"),
        ("/assets/app.js", "text/javascript", "X-Autheo-Demo-Token"),
    ]:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == 200
        assert expected_type in response.headers["Content-Type"]
        assert marker in body
    connection.close()


def test_mutation_requires_exact_loopback_host_origin_and_demo_token(running_server):
    server = running_server
    payload = {"action": "compute.simulate", "resource": "listing:demo-01", "amount_minor": 40}
    origin = f"http://127.0.0.1:{server.server_port}"

    status, _, _ = post(server, "/api/simulate", payload, token=server.demo_token, origin=origin,
                        host=f"localhost:{server.server_port}")
    assert status == 421
    status, _, _ = post(server, "/api/simulate", payload, token=server.demo_token,
                        origin="https://attacker.invalid")
    assert status == 403
    status, _, _ = post(server, "/api/simulate", payload, origin=origin)
    assert status == 403
    assert server.demo_session.state()["audit"]["count"] == 0


def test_http_rejects_bad_fields_and_non_json_without_receipt(running_server):
    server = running_server
    token = server.demo_token
    origin = f"http://127.0.0.1:{server.server_port}"
    status, _, body = post(
        server,
        "/api/simulate",
        {"action": "compute.simulate", "resource": "listing:demo-01", "amount_minor": True},
        token=token,
        origin=origin,
    )
    assert status == 400
    assert json.loads(body)["error"] == "request_failed_schema_validation"

    status, _, _ = post(
        server,
        "/api/simulate",
        {"action": "compute.simulate", "resource": "listing:demo-01", "amount_minor": 4},
        token=token,
        origin=origin,
        content_type="text/plain",
    )
    assert status == 415
    assert server.demo_session.state()["audit"]["count"] == 0


def test_http_actions_match_simulator_and_sample_sequence(running_server):
    server = running_server
    origin = f"http://127.0.0.1:{server.server_port}"
    status, headers, body = post(
        server,
        "/api/sample",
        {},
        token=server.demo_token,
        origin=origin,
    )
    payload = json.loads(body)
    assert status == 200
    assert headers.get("Access-Control-Allow-Origin") is None
    assert [item["decision"] for item in payload["results"]] == ["allow", "escalate", "block"]
    assert all(item["executed"] is False for item in payload["results"])
    assert payload["state"]["audit"]["count"] == 3

    status, _, body = post(
        server,
        "/api/simulate",
        {"action": "chain.read", "resource": "listing:demo-01", "amount_minor": 0},
        token=server.demo_token,
        origin=origin,
    )
    assert status == 200
    assert json.loads(body)["results"][0]["decision"] == "block"
