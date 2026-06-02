"""End-to-end HITL: create request -> approve -> mint -> verify with public key."""

from __future__ import annotations

from fastapi.testclient import TestClient

from common import InMemoryNonceStore, load_public_key_pem, now_epoch, verify_hitl_token


def _login(client: TestClient) -> dict[str, str]:
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _register_agent(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    reg = client.post("/agents", json={"name": "worker"}, headers=headers).json()
    return reg["id"], reg["api_key"]


def test_create_approve_mint_and_verify(client: TestClient) -> None:
    headers = _login(client)
    agent_id, api_key = _register_agent(client, headers)
    akey = {"X-Agent-Key": api_key}

    created = client.post(
        "/hitl/requests",
        json={"action": "fs.delete", "resource": "/work/x"},
        headers=akey,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "pending"
    assert body["agent_id"] == agent_id  # subject is the authenticated agent
    request_id = body["id"]

    approved = client.post(f"/hitl/requests/{request_id}/approve", headers=headers)
    assert approved.status_code == 200, approved.text
    token = approved.json()["token"]

    # Fetch the control-plane public key and verify the minted token end-to-end.
    pem = client.get("/hitl/public-key", headers=akey).json()["public_key_pem"]
    claims = verify_hitl_token(
        token,
        load_public_key_pem(pem.encode("utf-8")),
        expected_subject=agent_id,
        expected_tenant="default",
        expected_action="fs.delete",
        expected_resource="/work/x",
        now=now_epoch(),
        nonce_store=InMemoryNonceStore(),
    )
    assert claims.hitl_request_id == request_id

    # Approving an already-decided request is rejected.
    assert client.post(f"/hitl/requests/{request_id}/approve", headers=headers).status_code == 409


def test_request_requires_agent_key(client: TestClient) -> None:
    assert client.post("/hitl/requests", json={"action": "a", "resource": "r"}).status_code == 401


def test_deny_closes_request(client: TestClient) -> None:
    headers = _login(client)
    _, api_key = _register_agent(client, headers)
    request_id = client.post(
        "/hitl/requests",
        json={"action": "fs.delete", "resource": "/work/x"},
        headers={"X-Agent-Key": api_key},
    ).json()["id"]

    denied = client.post(f"/hitl/requests/{request_id}/deny", headers=headers)
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
