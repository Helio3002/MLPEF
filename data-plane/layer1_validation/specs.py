"""Per-tool argument specs — the allowlist of argument *shapes*.

Each `ToolSpec` declares exactly which arguments a tool accepts and the security
*kind* of each (so paths get jailed, commands stay argv-only, etc.). Unknown
arguments are rejected. In production these specs are supplied by the
control-plane Tool registry via the config bundle (Phase 8); the defaults below
are reference tools used to exercise Layer 1.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ArgKind(StrEnum):
    PATH = "path"  # jailed, lexically canonicalized
    COMMAND = "command"  # argv list, allowlisted program
    URL = "url"  # structural http(s) validation
    LITERAL = "literal"  # constrained token, no metacharacters
    TEXT = "text"  # free-form, only NUL rejected


@dataclass(frozen=True)
class ArgField:
    name: str
    kind: ArgKind
    required: bool = True


@dataclass(frozen=True)
class ToolSpec:
    tool: str
    fields: tuple[ArgField, ...]
    command_allowlist: tuple[str, ...] = ()


DEFAULT_TOOL_SPECS: dict[str, ToolSpec] = {
    "fs.read": ToolSpec("fs.read", (ArgField("path", ArgKind.PATH),)),
    "fs.write": ToolSpec(
        "fs.write",
        (ArgField("path", ArgKind.PATH), ArgField("content", ArgKind.TEXT)),
    ),
    "shell.exec": ToolSpec(
        "shell.exec",
        (ArgField("argv", ArgKind.COMMAND),),
        command_allowlist=("ls", "cat", "echo"),
    ),
    "http.get": ToolSpec("http.get", (ArgField("url", ArgKind.URL),)),
}
