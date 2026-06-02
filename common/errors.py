"""Fail-closed exception hierarchy.

Every security-relevant failure in the pipeline raises one of these. The pipeline
orchestrator (Phase 8) catches `MLPEFError` and converts it into a deny
`LayerDecision` via `Decision`-side helpers, guaranteeing that *any* exception,
timeout, or ambiguity becomes a logged denial rather than a silent allow.

Each error carries:
  * `reason_code` — the stable code recorded in audit + dashboards.
  * `layer`       — which stage raised it.
  * `security_event` — True when the failure indicates probable abuse (forgery,
    replay, traversal, injection) rather than a benign client mistake. Used to
    drive the "attack-attempt" dashboards and alerting.

These are class-level attributes so the mapping error-type -> reason-code is fixed
and auditable; instances only add a human-readable message and structured detail.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import JsonValue

from .enums import DenyReasonCode, LayerName


class MLPEFError(Exception):
    """Base for every deterministic, fail-closed error in the platform."""

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.INTERNAL_ERROR
    layer: ClassVar[LayerName] = LayerName.PIPELINE
    security_event: ClassVar[bool] = False

    def __init__(
        self,
        message: str,
        *,
        detail: dict[str, JsonValue] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        # `detail` is redacted-safe structured context for the audit record.
        # Never put secrets, raw tokens, or full payloads here.
        self.detail: dict[str, JsonValue] = dict(detail) if detail else {}


# --------------------------------------------------------------------------- #
# Layer 1 — input validation
# --------------------------------------------------------------------------- #
class ValidationFailure(MLPEFError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.SCHEMA_VIOLATION
    layer: ClassVar[LayerName] = LayerName.L1_VALIDATION


class UnknownTool(ValidationFailure):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.UNKNOWN_TOOL


class UnknownField(ValidationFailure):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.UNKNOWN_FIELD


class PathTraversalAttempt(ValidationFailure):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.PATH_TRAVERSAL
    security_event: ClassVar[bool] = True


class CommandInjectionAttempt(ValidationFailure):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.COMMAND_INJECTION
    security_event: ClassVar[bool] = True


# --------------------------------------------------------------------------- #
# Layer 2 — policy enforcement
# --------------------------------------------------------------------------- #
class PolicyDenied(MLPEFError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.POLICY_DENY
    layer: ClassVar[LayerName] = LayerName.L2_POLICY


class DefaultDenied(PolicyDenied):
    """No explicit allow matched — the default-deny floor fired."""

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.POLICY_DEFAULT_DENY


# --------------------------------------------------------------------------- #
# Layer 2 — HITL approval token
# --------------------------------------------------------------------------- #
class TokenError(MLPEFError):
    """Base for all approval-token verification failures."""

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_MALFORMED
    layer: ClassVar[LayerName] = LayerName.L2_POLICY


class TokenMalformed(TokenError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_MALFORMED


class TokenInvalidSignature(TokenError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_BAD_SIGNATURE
    security_event: ClassVar[bool] = True


class TokenExpired(TokenError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_EXPIRED


class TokenNotYetValid(TokenError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_NOT_YET_VALID


class TokenScopeMismatch(TokenError):
    """A validly-signed token presented for a different action/resource/subject.

    This is the Confused-Deputy / token-misuse signal: deny AND flag.
    """

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_SCOPE_MISMATCH
    security_event: ClassVar[bool] = True


class TokenReplay(TokenError):
    """A single-use token presented more than once."""

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TOKEN_REPLAY
    security_event: ClassVar[bool] = True


# --------------------------------------------------------------------------- #
# Layer 3 — sandbox execution
# --------------------------------------------------------------------------- #
class SandboxError(MLPEFError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.SANDBOX_FAILURE
    layer: ClassVar[LayerName] = LayerName.L3_SANDBOX


class SandboxTimeout(SandboxError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.SANDBOX_TIMEOUT


class ResourceLimitExceeded(SandboxError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.RESOURCE_LIMIT


class EgressBlocked(SandboxError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.EGRESS_BLOCKED
    security_event: ClassVar[bool] = True


# --------------------------------------------------------------------------- #
# Layer 4 — output filtering
# --------------------------------------------------------------------------- #
class OutputFilterError(MLPEFError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.OUTPUT_SECRET_DETECTED
    layer: ClassVar[LayerName] = LayerName.L4_FILTER


class SecretLeakDetected(OutputFilterError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.OUTPUT_SECRET_DETECTED
    security_event: ClassVar[bool] = True


class PIILeakDetected(OutputFilterError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.OUTPUT_PII_DETECTED


# --------------------------------------------------------------------------- #
# Cross-cutting
# --------------------------------------------------------------------------- #
class ConfigUnavailable(MLPEFError):
    """Control plane unreachable AND no usable last-known-good cached config.

    Fail closed: deny, never allow-all.
    """

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.CONFIG_UNAVAILABLE
    layer: ClassVar[LayerName] = LayerName.PIPELINE


class IdentityUnresolved(MLPEFError):
    """Agent credential did not resolve to a registered, active identity."""

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.IDENTITY_UNRESOLVED
    layer: ClassVar[LayerName] = LayerName.IDENTITY
    security_event: ClassVar[bool] = True


class AuditFailure(MLPEFError):
    """The unskippable audit write failed — the whole call must fail closed."""

    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.AUDIT_FAILURE
    layer: ClassVar[LayerName] = LayerName.L5_AUDIT


class PipelineTimeout(MLPEFError):
    reason_code: ClassVar[DenyReasonCode] = DenyReasonCode.TIMEOUT
    layer: ClassVar[LayerName] = LayerName.PIPELINE
