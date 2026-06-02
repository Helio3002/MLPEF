"""Adversarial path-traversal tests for the Layer 1 lexical jail."""

from __future__ import annotations

import pytest

from common.errors import PathTraversalAttempt, ValidationFailure
from layer1_validation.checks import canonicalize_and_jail

JAIL = "/work/agent"


def test_allows_paths_inside_the_jail() -> None:
    assert canonicalize_and_jail("notes.txt", JAIL) == "/work/agent/notes.txt"
    assert canonicalize_and_jail("sub/dir/file", JAIL) == "/work/agent/sub/dir/file"
    # `..` that stays within the jail is fine and canonicalizes.
    assert canonicalize_and_jail("a/b/../c", JAIL) == "/work/agent/a/c"


@pytest.mark.parametrize(
    "evil",
    [
        "../etc/passwd",
        "../../../../etc/passwd",
        "..",
        "/etc/passwd",  # absolute escape
        "a/../../b",  # climbs out
        "subdir/../../escape",
    ],
)
def test_rejects_traversal(evil: str) -> None:
    with pytest.raises(PathTraversalAttempt):
        canonicalize_and_jail(evil, JAIL)


@pytest.mark.parametrize("evil", ["..%2fetc", "%2e%2e/etc", "%2e%2e%2fpasswd", "%2557"])
def test_rejects_percent_encoded(evil: str) -> None:
    with pytest.raises(PathTraversalAttempt):
        canonicalize_and_jail(evil, JAIL)


@pytest.mark.parametrize("evil", ["a\x00b", "a\nb", "x\x1f", "..\\..\\x", "a\\b"])
def test_rejects_control_and_backslash(evil: str) -> None:
    with pytest.raises(PathTraversalAttempt):
        canonicalize_and_jail(evil, JAIL)


def test_rejects_jail_prefix_confusion() -> None:
    # "/work/agent-evil/x" must NOT be accepted when the jail is "/work/agent".
    with pytest.raises(PathTraversalAttempt):
        canonicalize_and_jail("../agent-evil/x", JAIL)


def test_rejects_root_jail() -> None:
    with pytest.raises(ValidationFailure):
        canonicalize_and_jail("x", "/")
