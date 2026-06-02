"""Audit ingestion, querying, and end-to-end tamper detection via the control-api."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import text


def _login(client: TestClient) -> dict[str, str]:
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _register_agent(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    reg = client.post("/agents", json={"name": "emitter"}, headers=headers).json()
    return reg["id"], reg["api_key"]


def _event(agent_id: str, i: int, *, verdict: str = "deny") -> dict[str, object]:
    return {
        "correlation_id": f"intent-{i}",
        "timestamp": 1_700_000_000 + i,
        "tenant": "default",
        "agent_id": agent_id,
        "ingress": "rest",
        "tool": "filesystem",
        "action": "fs.delete",
        "resource": f"/data/{i}",
        "final_verdict": verdict,
    }


def test_ingest_builds_a_verifiable_chain(client: TestClient) -> None:
    headers = _login(client)
    agent_id, api_key = _register_agent(client, headers)
    akey = {"X-Agent-Key": api_key}

    r0 = client.post("/audit", json=_event(agent_id, 0), headers=akey)
    assert r0.status_code == 201, r0.text
    assert r0.json()["seq"] == 0
    assert r0.json()["prev_hash"] == "0" * 64

    r1 = client.post("/audit", json=_event(agent_id, 1), headers=akey)
    assert r1.json()["seq"] == 1
    assert r1.json()["prev_hash"] == r0.json()["record_hash"]  # chained

    verify = client.get("/audit/verify", headers=headers).json()
    assert verify["ok"] is True
    assert verify["records_checked"] == 2


def test_ingest_requires_matching_agent_credential(client: TestClient) -> None:
    headers = _login(client)
    agent_id, api_key = _register_agent(client, headers)

    # Event claims a different agent than the credential → 403.
    forged = client.post(
        "/audit", json=_event("someone-else", 0), headers={"X-Agent-Key": api_key}
    )
    assert forged.status_code == 403

    # No agent key at all → 401 (fail closed).
    assert client.post("/audit", json=_event(agent_id, 0)).status_code == 401


def test_filter_by_outcome(client: TestClient) -> None:
    headers = _login(client)
    agent_id, api_key = _register_agent(client, headers)
    akey = {"X-Agent-Key": api_key}
    client.post("/audit", json=_event(agent_id, 0, verdict="allow"), headers=akey)
    client.post("/audit", json=_event(agent_id, 1, verdict="deny"), headers=akey)

    denied = client.get("/audit", params={"outcome": "deny"}, headers=headers).json()
    assert len(denied) == 1
    assert denied[0]["event"]["final_verdict"] == "deny"


def test_verify_detects_content_tampering(client: TestClient) -> None:
    headers = _login(client)
    agent_id, api_key = _register_agent(client, headers)
    akey = {"X-Agent-Key": api_key}
    client.post("/audit", json=_event(agent_id, 0, verdict="deny"), headers=akey)
    client.post("/audit", json=_event(agent_id, 1, verdict="deny"), headers=akey)
    assert client.get("/audit/verify", headers=headers).json()["ok"] is True

    # Cover up the first denial by flipping it to "allow" directly in the store.
    stored = client.get("/audit", headers=headers).json()
    forged_event = stored[0]["event"]
    forged_event["final_verdict"] = "allow"
    engine = client.app.state.test_engine
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE audit_records SET event = :e WHERE seq = 0"),
            {"e": json.dumps(forged_event)},
        )

    verify = client.get("/audit/verify", headers=headers).json()
    assert verify["ok"] is False
    assert verify["first_broken_seq"] == 0
