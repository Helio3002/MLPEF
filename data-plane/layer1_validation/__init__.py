"""Layer 1 — deterministic input validation (allowlist, jail, argv-only)."""

from __future__ import annotations

from .specs import DEFAULT_TOOL_SPECS, ArgField, ArgKind, ToolSpec
from .validator import validate

__all__ = ["DEFAULT_TOOL_SPECS", "ArgField", "ArgKind", "ToolSpec", "validate"]
