"""Smoke tests for the control-api core flows."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _login(client: TestClient) -> dict[str, str]:
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"


def test_bad_login_rejected(client: TestClient) -> None:
    resp = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_register_agent_returns_key_once_and_assigns_default_profile(client: TestClient) -> None:
    headers = _login(client)
    resp = client.post("/agents", json={"name": "agent-one"}, headers=headers)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["profile_id"] == "default-locked-down"  # deny-most default
    assert body["api_key"].startswith("mlpef_")

    # Re-reading the agent must not expose the credential.
    detail = client.get(f"/agents/{body['id']}", headers=headers)
    assert detail.status_code == 200
    assert "api_key" not in detail.json()


def test_config_bundle_requires_matching_agent_key(client: TestClient) -> None:
    headers = _login(client)
    reg = client.post("/agents", json={"name": "agent-two"}, headers=headers).json()
    agent_id, api_key = reg["id"], reg["api_key"]

    ok = client.get(f"/agents/{agent_id}/config-bundle", headers={"X-Agent-Key": api_key})
    assert ok.status_code == 200, ok.text
    bundle = ok.json()
    assert bundle["agent_id"] == agent_id
    assert bundle["profile"]["tool_allowlist"] == []  # locked down
    assert bundle["etag"]

    # No agent key -> 401 (fail closed).
    assert client.get(f"/agents/{agent_id}/config-bundle").status_code == 401


def test_rbac_blocks_unauthenticated_write(client: TestClient) -> None:
    assert client.post("/agents", json={"name": "nope"}).status_code == 401


def test_profile_delete_blocked_while_in_use(client: TestClient) -> None:
    headers = _login(client)
    client.post("/agents", json={"name": "agent-three"}, headers=headers)
    resp = client.delete("/profiles/default-locked-down", headers=headers)
    assert resp.status_code == 409  # in use by an agent
