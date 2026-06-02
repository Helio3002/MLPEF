"""Layer 1 orchestration: validate an Intent against the agent's resolved profile.

Allowlist-first and fail-closed: an unknown tool, unknown argument, bad type, or
any check failure becomes a coded deny `LayerDecision` (never an exception that
escapes). The tool allowlist and path jail both come from the profile, not from
hardcoded values.
"""

from __future__ import annotations

from typing import Any

from common import (
    Intent,
    LayerDecision,
    LayerName,
    PolicyProfile,
    ResourceKind,
    Stopwatch,
)
from common.errors import MLPEFError, UnknownField, UnknownTool, ValidationFailure

from . import checks
from .specs import DEFAULT_TOOL_SPECS, ArgField, ArgKind, ToolSpec


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationFailure(f"argument {field!r} must be a string")
    return value


def _path_jail(profile: PolicyProfile) -> str | None:
    for scope in profile.resource_scopes:
        if scope.kind is ResourceKind.PATH and scope.jail_prefix:
            return scope.jail_prefix
    return None


def _validate_field(field: ArgField, value: Any, *, jail: str | None, spec: ToolSpec) -> None:
    if field.kind is ArgKind.PATH:
        path = _require_str(value, field.name)
        if jail is None:
            raise ValidationFailure(f"no path scope configured for {field.name!r}")
        checks.canonicalize_and_jail(path, jail)
    elif field.kind is ArgKind.COMMAND:
        checks.validate_argv(value, command_allowlist=spec.command_allowlist)
    elif field.kind is ArgKind.URL:
        checks.validate_url(_require_str(value, field.name), field=field.name)
    elif field.kind is ArgKind.LITERAL:
        checks.validate_literal(_require_str(value, field.name), field=field.name)
    elif field.kind is ArgKind.TEXT:
        checks.validate_text(_require_str(value, field.name), field=field.name)
    else:  # defensive: an unhandled kind must deny, never silently pass
        raise ValidationFailure(f"unhandled argument kind for {field.name!r}: {field.kind}")


def _validate(intent: Intent, profile: PolicyProfile, specs: dict[str, ToolSpec]) -> None:
    if intent.tool not in profile.tool_allowlist:
        raise UnknownTool(
            f"tool not in profile allowlist: {intent.tool!r}",
            detail={"tool": intent.tool},
        )
    spec = specs.get(intent.tool)
    if spec is None:
        raise UnknownTool(f"no validation spec registered for tool: {intent.tool!r}")

    allowed = {field.name for field in spec.fields}
    extra = sorted(set(intent.arguments) - allowed)
    if extra:
        raise UnknownField(f"unexpected argument(s): {extra}", detail={"extra": extra})

    jail = _path_jail(profile)
    for field in spec.fields:
        if field.name not in intent.arguments:
            if field.required:
                raise ValidationFailure(f"missing required argument: {field.name!r}")
            continue
        _validate_field(field, intent.arguments[field.name], jail=jail, spec=spec)


def validate(
    intent: Intent,
    profile: PolicyProfile,
    *,
    specs: dict[str, ToolSpec] | None = None,
) -> LayerDecision:
    registry = specs if specs is not None else DEFAULT_TOOL_SPECS
    with Stopwatch() as stopwatch:
        try:
            _validate(intent, profile, registry)
        except MLPEFError as exc:
            return LayerDecision.from_error(exc, elapsed_ms=stopwatch.elapsed_ms)
    return LayerDecision.allow(LayerName.L1_VALIDATION, elapsed_ms=stopwatch.elapsed_ms)
