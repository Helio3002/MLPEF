"""End-to-end Layer 1 validation against a resolved profile."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from common import (
    DenyReasonCode,
    IngressSource,
    Intent,
    PolicyProfile,
    ResourceKind,
    ResourceScope,
    Verdict,
)
from layer1_validation import ArgField, ArgKind, ToolSpec, validate


def _profile(tools: list[str], jail: str | None = "/work/agent") -> PolicyProfile:
    scopes = (
        [ResourceScope(kind=ResourceKind.PATH, jail_prefix=jail)] if jail is not None else []
    )
    return PolicyProfile(
        profile_id="p",
        name="p",
        tenant="t",
        tool_allowlist=list(tools),
        resource_scopes=scopes,
    )


def _intent(tool: str, arguments: Mapping[str, Any]) -> Intent:
    return Intent(
        intent_id="i",
        agent_id="a",
        tenant="t",
        tool=tool,
        action=tool,
        resource="-",
        ingress=IngressSource.REST,
        received_at=1,
        arguments=dict(arguments),
    )


def test_allows_valid_read() -> None:
    decision = validate(_intent("fs.read", {"path": "notes.txt"}), _profile(["fs.read"]))
    assert decision.verdict is Verdict.ALLOW


def test_denies_tool_not_in_allowlist() -> None:
    decision = validate(_intent("fs.read", {"path": "notes.txt"}), _profile([]))
    assert decision.verdict is Verdict.DENY
    assert decision.reason_code is DenyReasonCode.UNKNOWN_TOOL


def test_denies_unknown_argument() -> None:
    decision = validate(
        _intent("fs.read", {"path": "x", "evil": 1}), _profile(["fs.read"])
    )
    assert decision.reason_code is DenyReasonCode.UNKNOWN_FIELD


def test_path_traversal_is_a_security_event() -> None:
    decision = validate(
        _intent("fs.read", {"path": "../../etc/passwd"}), _profile(["fs.read"])
    )
    assert decision.verdict is Verdict.DENY
    assert decision.reason_code is DenyReasonCode.PATH_TRAVERSAL
    assert decision.security_event is True


def test_shell_string_is_command_injection() -> None:
    decision = validate(
        _intent("shell.exec", {"argv": "rm -rf / ; curl evil"}), _profile(["shell.exec"])
    )
    assert decision.reason_code is DenyReasonCode.COMMAND_INJECTION
    assert decision.security_event is True


def test_allows_argv_list() -> None:
    decision = validate(
        _intent("shell.exec", {"argv": ["ls", "-la"]}), _profile(["shell.exec"])
    )
    assert decision.verdict is Verdict.ALLOW


def test_literal_kind_via_custom_spec() -> None:
    specs = {"db.lookup": ToolSpec("db.lookup", (ArgField("table", ArgKind.LITERAL),))}
    profile = _profile(["db.lookup"])
    ok = validate(_intent("db.lookup", {"table": "users"}), profile, specs=specs)
    assert ok.verdict is Verdict.ALLOW
    injected = validate(
        _intent("db.lookup", {"table": "users; DROP TABLE x"}), profile, specs=specs
    )
    assert injected.reason_code is DenyReasonCode.COMMAND_INJECTION
