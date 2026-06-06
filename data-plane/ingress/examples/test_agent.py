#!/usr/bin/env python3
"""End-to-end self-test for a running MLPEF stack.

Drives a real agent (through the proxy) and an admin (through the control-api) to
exercise the whole pipeline and print a PASS/FAIL report:

  - ALLOW         a permitted, in-jail tool call
  - default-deny  a tool not in the profile allowlist
  - L1 traversal  a path that escapes the jail            (security event)
  - L1 injection  a command outside the argv allowlist    (security event)
  - HITL          gate -> approve -> retry-with-token -> ALLOW
  - HITL replay   reusing the one-time token              (security event)
  - R-12          the config bundle is Ed25519-signed
  - L5            the audit hash-chain verifies

It acts as the **seeded demo agent** because docker-compose binds the proxy's audit
emit to that agent's key (THREAT_MODEL.md R-17): a brand-new agent's calls would
fail closed on the audit write. The tester temporarily reassigns the demo agent to
a permissive `e2e-test` profile, waits out the config-cache TTL, runs the battery,
then restores the deny-most default.

Run it against a running stack (inside the Codespace / on the server, not the
browser, so localhost works):

    python data-plane/ingress/examples/test_agent.py
    # or override:
    python data-plane/ingress/examples/test_agent.py \
        --control-api http://localhost:8080 --proxy http://localhost:8090 \
        --admin-user admin --admin-pass <pw> \
        --agent-id sample-agent-demo --agent-key <MLPEF_SAMPLE_AGENT_API_KEY>

Defaults come from the env (MLPEF_ADMIN_USERNAME/PASSWORD, MLPEF_SAMPLE_AGENT_ID/
API_KEY) and fall back to the .env.example demo values. Needs `httpx`
(`pip install -e ".[proxy]"`). Exit code 0 iff every check passes.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

import httpx

_PROFILE_ID = "e2e-test"
_TEST_PROFILE: dict[str, Any] = {
    "profile_id": _PROFILE_ID,
    "name": "E2E test (permissive)",
    "tenant": "default",
    "tool_allowlist": ["fs.read", "fs.write", "shell.exec", "http.get"],
    "resource_scopes": [{"kind": "path", "jail_prefix": "/work"}],
    "hitl_rules": [{"action_pattern": "fs.write", "resource_pattern": "*"}],
}
_TIMEOUT = 20.0


def _login(control_api: str, user: str, password: str) -> str:
    resp = httpx.post(
        f"{control_api}/auth/login",
        json={"username": user, "password": password},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return str(resp.json()["token"])


def _execute(
    proxy: str,
    agent_id: str,
    key: str,
    *,
    tool: str,
    action: str,
    resource: str,
    arguments: dict[str, Any],
    approval_token: str | None = None,
) -> dict[str, Any]:
    resp = httpx.post(
        f"{proxy}/v1/execute",
        headers={"X-Agent-Id": agent_id, "X-Agent-Key": key},
        json={
            "tool": tool,
            "action": action,
            "resource": resource,
            "arguments": arguments,
            "approval_token": approval_token,
        },
        timeout=_TIMEOUT,
    )
    body: dict[str, Any] = resp.json()
    return body


def _await_profile_active(proxy: str, agent_id: str, key: str, *, timeout: float = 50.0) -> bool:
    """Poll a known-allowed call until it returns ALLOW, so we don't race the
    proxy's config-cache TTL after reassigning the agent's profile."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            body = _execute(
                proxy, agent_id, key, tool="fs.read", action="fs.read",
                resource="/work/_ready.txt", arguments={"path": "/work/_ready.txt"},
            )
            if body.get("verdict") == "allow":
                return True
        except httpx.HTTPError:
            pass
        time.sleep(3.0)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MLPEF end-to-end self-test")
    parser.add_argument("--control-api",
                        default=os.environ.get("MLPEF_CONTROL_API", "http://localhost:8080"))
    parser.add_argument("--proxy", default=os.environ.get("MLPEF_PROXY", "http://localhost:8090"))
    parser.add_argument("--admin-user", default=os.environ.get("MLPEF_ADMIN_USERNAME", "admin"))
    parser.add_argument("--admin-pass", default=os.environ.get("MLPEF_ADMIN_PASSWORD", "admin"))
    parser.add_argument("--agent-id",
                        default=os.environ.get("MLPEF_SAMPLE_AGENT_ID", "sample-agent-demo"))
    parser.add_argument("--agent-key",
                        default=os.environ.get("MLPEF_SAMPLE_AGENT_API_KEY",
                                               "change-me-demo-agent-key-0123456789"))
    args = parser.parse_args(argv)

    control_api: str = args.control_api.rstrip("/")
    proxy: str = args.proxy.rstrip("/")
    agent_id: str = args.agent_id
    key: str = args.agent_key

    checks: list[tuple[str, bool]] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok))
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""))

    def expect(
        name: str,
        *,
        tool: str,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        token: str | None = None,
        want_verdict: str,
        want_reason: str | None = None,
        want_security: bool | None = None,
    ) -> dict[str, Any]:
        try:
            body = _execute(proxy, agent_id, key, tool=tool, action=action, resource=resource,
                            arguments=arguments, approval_token=token)
        except httpx.HTTPError as exc:
            record(name, False, f"request error: {exc}")
            return {}
        ok = body.get("verdict") == want_verdict
        if want_reason is not None:
            ok = ok and body.get("reason_code") == want_reason
        if want_security is not None:
            ok = ok and bool(body.get("security_event")) == want_security
        record(name, ok, f"verdict={body.get('verdict')} reason={body.get('reason_code')} "
                         f"security={body.get('security_event')}")
        return body

    print(f"MLPEF end-to-end self-test\n  control-api={control_api}  proxy={proxy}  "
          f"agent={agent_id}\n")

    # --- Setup (admin) ---------------------------------------------------- #
    try:
        admin_token = _login(control_api, args.admin_user, args.admin_pass)
    except httpx.HTTPError as exc:
        print(f"FATAL: admin login failed ({exc}). Is the control-api up and the password right?",
              file=sys.stderr)
        return 2
    ah = {"Authorization": f"Bearer {admin_token}"}

    try:
        created = httpx.post(f"{control_api}/profiles", headers=ah, json=_TEST_PROFILE,
                             timeout=_TIMEOUT)
        if created.status_code == 409:
            httpx.put(f"{control_api}/profiles/{_PROFILE_ID}", headers=ah, json=_TEST_PROFILE,
                      timeout=_TIMEOUT).raise_for_status()
        else:
            created.raise_for_status()
        httpx.post(f"{control_api}/agents/{agent_id}/profile", headers=ah,
                   json={"profile_id": _PROFILE_ID}, timeout=_TIMEOUT).raise_for_status()
        print(f"[setup] agent '{agent_id}' -> profile '{_PROFILE_ID}' (permissive, fs.write gated)")
    except httpx.HTTPError as exc:
        print(f"FATAL: setup failed ({exc}).", file=sys.stderr)
        return 2

    print("[setup] waiting for the proxy config cache to pick up the new profile...")
    if not _await_profile_active(proxy, agent_id, key):
        print("FATAL: agent never became ALLOWed - proxy unreachable, or config cache TTL too "
              "long. Check `docker compose ps` / proxy logs.", file=sys.stderr)
        _restore(control_api, ah, agent_id)
        return 2

    # --- Scenarios -------------------------------------------------------- #
    print("\nLayer 1 + Layer 2 (decision path):")
    expect("ALLOW  fs.read (in jail, allowlisted)", tool="fs.read", action="fs.read",
           resource="/work/notes.txt", arguments={"path": "/work/notes.txt"},
           want_verdict="allow")
    expect("ALLOW  shell.exec echo (allowlisted argv)", tool="shell.exec", action="shell.exec",
           resource="-", arguments={"argv": ["echo", "hi"]}, want_verdict="allow")
    expect("DENY   default-deny (tool not in allowlist)", tool="fs.delete", action="fs.delete",
           resource="/work/x", arguments={"path": "/work/x"},
           want_verdict="deny", want_reason="unknown_tool")
    expect("BLOCK  path traversal (escapes /work jail)", tool="fs.read", action="fs.read",
           resource="/etc/passwd", arguments={"path": "/etc/passwd"},
           want_verdict="deny", want_reason="path_traversal", want_security=True)
    expect("BLOCK  command injection (program not allowlisted)", tool="shell.exec",
           action="shell.exec", resource="-", arguments={"argv": ["rm", "-rf", "/"]},
           want_verdict="deny", want_reason="command_injection", want_security=True)

    print("\nHuman-in-the-loop (HITL):")
    expect("GATE   fs.write requires approval (no token)", tool="fs.write", action="fs.write",
           resource="/work/x.txt", arguments={"path": "/work/x.txt", "content": "e2e"},
           want_verdict="hitl_required", want_reason="hitl_required")

    token: str | None = None
    try:
        req = httpx.post(f"{control_api}/hitl/requests", headers={"X-Agent-Key": key},
                         json={"action": "fs.write", "resource": "/work/x.txt"}, timeout=_TIMEOUT)
        req.raise_for_status()
        request_id = req.json()["id"]
        appr = httpx.post(f"{control_api}/hitl/requests/{request_id}/approve", headers=ah,
                          timeout=_TIMEOUT)
        appr.raise_for_status()
        token = str(appr.json()["token"])
        record("APPROVE control plane mints a scoped token", True, f"request={request_id}")
    except httpx.HTTPError as exc:
        record("APPROVE control plane mints a scoped token", False, f"error: {exc}")

    if token:
        write_args = {"path": "/work/x.txt", "content": "e2e"}
        expect("ALLOW  retry fs.write WITH token", tool="fs.write", action="fs.write",
               resource="/work/x.txt", arguments=write_args, token=token, want_verdict="allow")
        expect("BLOCK  replay the same token", tool="fs.write", action="fs.write",
               resource="/work/x.txt", arguments=write_args, token=token,
               want_verdict="deny", want_reason="token_replay", want_security=True)

    print("\nConfig integrity (R-12) + Audit (L5):")
    try:
        bundle = httpx.get(f"{control_api}/agents/{agent_id}/config-bundle",
                           headers={"X-Agent-Key": key}, timeout=_TIMEOUT)
        bundle.raise_for_status()
        signed = bool(bundle.json().get("signature"))
        record("SIGNED config bundle carries an Ed25519 signature", signed,
               "signature present" if signed else "MISSING")
    except httpx.HTTPError as exc:
        record("SIGNED config bundle carries an Ed25519 signature", False, f"error: {exc}")

    try:
        verify = httpx.get(f"{control_api}/audit/verify", headers=ah, timeout=_TIMEOUT)
        verify.raise_for_status()
        vj = verify.json()
        record("CHAIN audit hash-chain verifies intact", bool(vj.get("ok")),
               f"records_checked={vj.get('records_checked')}")
    except httpx.HTTPError as exc:
        record("CHAIN audit hash-chain verifies intact", False, f"error: {exc}")

    # --- Restore + report ------------------------------------------------- #
    _restore(control_api, ah, agent_id)

    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    print(f"\n{'=' * 60}\nRESULT: {passed}/{total} checks passed.")
    if passed != total:
        print("Some checks failed - see [FAIL] lines above.")
        return 1
    print("All checks passed - MLPEF is enforcing end to end.")
    return 0


def _restore(control_api: str, admin_headers: dict[str, str], agent_id: str) -> None:
    """Best-effort: put the demo agent back on the deny-most default profile."""
    try:
        httpx.post(f"{control_api}/agents/{agent_id}/profile", headers=admin_headers,
                   json={"profile_id": "default-locked-down"}, timeout=_TIMEOUT)
        print("[cleanup] restored agent to 'default-locked-down'.")
    except httpx.HTTPError:
        print("[cleanup] WARNING: could not restore the agent profile; do it in the UI.")


if __name__ == "__main__":
    raise SystemExit(main())
