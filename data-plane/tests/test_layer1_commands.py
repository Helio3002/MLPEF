"""Adversarial command-injection tests for Layer 1."""

from __future__ import annotations

import pytest

from common.errors import CommandInjectionAttempt
from layer1_validation.checks import validate_argv, validate_literal


def test_argv_allows_allowlisted_command() -> None:
    assert validate_argv(["ls", "-la", "/work"], command_allowlist=("ls", "cat")) == [
        "ls",
        "-la",
        "/work",
    ]


def test_argv_rejects_shell_string() -> None:
    # The classic injection: a single shell string instead of an argv list.
    with pytest.raises(CommandInjectionAttempt):
        validate_argv("ls -la ; rm -rf /", command_allowlist=("ls",))


@pytest.mark.parametrize(
    "bad",
    [
        [],  # empty
        ["rm", "-rf", "/"],  # program not allowlisted
        ["ls", 3],  # non-string element
        ["ls", "a\x00b"],  # NUL in element
    ],
)
def test_argv_rejects_bad_inputs(bad: object) -> None:
    with pytest.raises(CommandInjectionAttempt):
        validate_argv(bad, command_allowlist=("ls", "cat", "echo"))


@pytest.mark.parametrize("good", ["report", "file_1", "Table.Name-2"])
def test_literal_allows_plain_tokens(good: str) -> None:
    assert validate_literal(good, field="x") == good


@pytest.mark.parametrize(
    "bad",
    ["a;b", "$(whoami)", "a|b", "a b", "x`y`", "a&&b", "a>b", "a'b"],
)
def test_literal_rejects_metacharacters(bad: str) -> None:
    with pytest.raises(CommandInjectionAttempt):
        validate_literal(bad, field="x")
