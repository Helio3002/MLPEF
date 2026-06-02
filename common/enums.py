"""Shared enumerations used across the data plane and control plane.

These are the stable vocabulary for decisions and audit records. Reason codes in
particular are consumed by dashboards (e.g. attack-attempt counters), so their
string values are part of the wire/audit contract — change them deliberately.
"""

from __future__ import annotations

from enum import StrEnum


class Verdict(StrEnum):
    """Outcome of a single layer or the whole pipeline."""

    ALLOW = "allow"
    DENY = "deny"
    # A destructive/state-altering action that requires human approval. The
    # current call is NOT executed; an HITLRequest is created and the agent must
    # retry with a scoped, signed approval token. HITL_REQUIRED is therefore a
    # form of deny for the in-flight call, tracked separately for visibility.
    HITL_REQUIRED = "hitl_required"


class LayerName(StrEnum):
    """Identifies which stage produced a decision, for the audit trace."""

    INGRESS = "ingress"
    IDENTITY = "identity"
    L1_VALIDATION = "l1_validation"
    L2_POLICY = "l2_policy"
    L3_SANDBOX = "l3_sandbox"
    L4_FILTER = "l4_filter"
    L5_AUDIT = "l5_audit"
    PIPELINE = "pipeline"


class IngressSource(StrEnum):
    """Which ingress adapter normalized the request into an Intent.

    All adapters converge on the identical five-layer pipeline; this field only
    records provenance for the audit trail and per-adapter dashboards.
    """

    MCP = "mcp"
    OPENAI_COMPAT = "openai_compat"
    REST = "rest"
    SDK_SHIM = "sdk_shim"


class Severity(StrEnum):
    """Residual-risk / security-event severity (mirrors THREAT_MODEL.md)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DenyReasonCode(StrEnum):
    """Stable, machine-readable reason for a deny/HITL outcome.

    Grouped by the layer that most commonly raises them. Dashboards aggregate on
    these codes, so prefer adding a new code over overloading an existing one.
    """

    # --- Layer 1: input validation ---
    SCHEMA_VIOLATION = "schema_violation"
    UNKNOWN_TOOL = "unknown_tool"
    UNKNOWN_FIELD = "unknown_field"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    ARGUMENT_SHAPE = "argument_shape"

    # --- Layer 2: policy + HITL token ---
    POLICY_DEFAULT_DENY = "policy_default_deny"
    POLICY_DENY = "policy_deny"
    HITL_REQUIRED = "hitl_required"
    TOKEN_MALFORMED = "token_malformed"
    TOKEN_BAD_SIGNATURE = "token_bad_signature"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"
    TOKEN_SCOPE_MISMATCH = "token_scope_mismatch"
    TOKEN_REPLAY = "token_replay"

    # --- Layer 3: sandbox execution ---
    SANDBOX_FAILURE = "sandbox_failure"
    SANDBOX_TIMEOUT = "sandbox_timeout"
    RESOURCE_LIMIT = "resource_limit"
    EGRESS_BLOCKED = "egress_blocked"

    # --- Layer 4: output filtering ---
    OUTPUT_SECRET_DETECTED = "output_secret_detected"
    OUTPUT_PII_DETECTED = "output_pii_detected"
    OUTPUT_INJECTION_NEUTRALIZED = "output_injection_neutralized"

    # --- cross-cutting / fail-closed ---
    CONFIG_UNAVAILABLE = "config_unavailable"
    IDENTITY_UNRESOLVED = "identity_unresolved"
    AUDIT_FAILURE = "audit_failure"
    TIMEOUT = "timeout"
    INTERNAL_ERROR = "internal_error"
