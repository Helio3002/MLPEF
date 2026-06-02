"""Deterministic, no-I/O input checks for Layer 1.

Path jailing here is **lexical**: it collapses `.`/`..`, and rejects
percent-encoding, backslashes, NUL/control bytes, and anything that escapes the
jail prefix — without touching the filesystem. True symlink resolution needs I/O
and the real (sandbox) filesystem, so it is enforced by the Layer 3 sandbox
(read-only rootfs + jailed mount), not here (see THREAT_MODEL.md R-20). Staying
I/O-free is what keeps Layer 1 on the sub-10ms decision hot path.

Command-injection defense: commands are `argv` lists (never shell strings), and
literal fields reject shell metacharacters. `argv` *elements* are NOT
metacharacter-filtered — they are passed to exec, not a shell, so the only
requirement is that they never form a shell string.
"""

from __future__ import annotations

import posixpath
from urllib.parse import unquote, urlsplit

from common.errors import CommandInjectionAttempt, PathTraversalAttempt, ValidationFailure

# Characters that are dangerous when a value is interpolated into a shell/command.
_SHELL_METACHARACTERS = frozenset(";|&$<>(){}[]!*?#~" + "`" + "\\" + "'" + '"')
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def _has_control_bytes(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def canonicalize_and_jail(raw: str, jail_prefix: str) -> str:
    """Return the lexically-canonical path, or raise if it escapes the jail."""
    if "\x00" in raw or _has_control_bytes(raw):
        raise PathTraversalAttempt("control or NUL byte in path")
    if "%" in raw and unquote(raw) != raw:
        raise PathTraversalAttempt("percent-encoded path rejected")
    if "\\" in raw:
        raise PathTraversalAttempt("backslash in path rejected")

    jail = posixpath.normpath(jail_prefix)
    if not posixpath.isabs(jail) or jail == "/":
        raise ValidationFailure("jail prefix must be an absolute, non-root path")

    resolved = posixpath.normpath(posixpath.join(jail, raw))
    if resolved != jail and not resolved.startswith(jail + "/"):
        raise PathTraversalAttempt(
            "path escapes the jail",
            detail={"jail": jail, "resolved": resolved},
        )
    return resolved


def validate_argv(argv: object, *, command_allowlist: tuple[str, ...]) -> list[str]:
    """Require a non-empty argv list (never a shell string); enforce the
    command allowlist on argv[0]."""
    if not isinstance(argv, list) or not argv:
        raise CommandInjectionAttempt("command must be a non-empty argv list, not a shell string")
    if not all(isinstance(element, str) for element in argv):
        raise CommandInjectionAttempt("argv elements must all be strings")
    if any("\x00" in element for element in argv):
        raise CommandInjectionAttempt("NUL byte in argv element")
    program = argv[0]
    if command_allowlist and program not in command_allowlist:
        raise CommandInjectionAttempt(
            f"command not in allowlist: {program!r}",
            detail={"allowed": list(command_allowlist)},
        )
    return [str(element) for element in argv]


def validate_literal(value: str, *, field: str) -> str:
    """A constrained token (e.g. an identifier) — no metacharacters/whitespace."""
    if "\x00" in value or _has_control_bytes(value):
        raise CommandInjectionAttempt(f"control or NUL byte in {field!r}")
    offending = sorted(set(value) & _SHELL_METACHARACTERS)
    if offending:
        raise CommandInjectionAttempt(
            f"shell metacharacters in {field!r}: {''.join(offending)}"
        )
    if any(ch.isspace() for ch in value):
        raise CommandInjectionAttempt(f"whitespace not allowed in {field!r}")
    return value


def validate_text(value: str, *, field: str) -> str:
    """Free-form text (e.g. file contents). Only NUL is rejected."""
    if "\x00" in value:
        raise ValidationFailure(f"NUL byte in {field!r}")
    return value


def validate_url(raw: str, *, field: str) -> str:
    """Structural URL validation only. Host/egress allowlisting is Layer 2."""
    if "\x00" in raw or _has_control_bytes(raw) or any(ch.isspace() for ch in raw):
        raise ValidationFailure(f"control or whitespace byte in {field!r}")
    parts = urlsplit(raw)
    if parts.scheme not in _ALLOWED_URL_SCHEMES:
        raise ValidationFailure(f"URL scheme not allowed in {field!r}: {parts.scheme!r}")
    if not parts.hostname:
        raise ValidationFailure(f"URL has no host in {field!r}")
    return raw
