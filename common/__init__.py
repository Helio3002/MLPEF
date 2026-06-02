"""MLPEF shared types and primitives.

Everything in `common` is dependency-light and import-safe for both the data
plane (proxy) and the control plane (control-api). It carries no framework code
(no FastAPI, no SQLAlchemy) so it can sit on the decision hot path.
"""

from __future__ import annotations

from .audit import (
    GENESIS_PREV_HASH,
    AuditEvent,
    AuditRecord,
    ChainVerification,
    build_audit_event,
    compute_record_hash,
    seal_event,
    verify_chain,
)
from .decision import LayerDecision, PipelineResult
from .enums import (
    DenyReasonCode,
    IngressSource,
    LayerName,
    Severity,
    Verdict,
)
from .errors import (
    AuditFailure,
    CommandInjectionAttempt,
    ConfigUnavailable,
    DefaultDenied,
    EgressBlocked,
    IdentityUnresolved,
    MLPEFError,
    PathTraversalAttempt,
    PIILeakDetected,
    PipelineTimeout,
    PolicyDenied,
    ResourceLimitExceeded,
    SandboxError,
    SandboxTimeout,
    SecretLeakDetected,
    TokenError,
    TokenExpired,
    TokenInvalidSignature,
    TokenMalformed,
    TokenNotYetValid,
    TokenReplay,
    TokenScopeMismatch,
    UnknownTool,
    ValidationFailure,
)
from .intent import Intent, Provenance
from .profiles import (
    ConfigBundle,
    HITLRule,
    OutputFilterPolicy,
    PolicyProfile,
    ResourceKind,
    ResourceScope,
    SandboxLimits,
    default_locked_down_profile,
)
from .timing import PhaseTimings, Stopwatch, monotonic_ms, now_epoch
from .tokens import (
    HITLTokenClaims,
    InMemoryNonceStore,
    NonceStore,
    generate_keypair,
    load_private_key_pem,
    load_public_key_pem,
    mint_hitl_token,
    private_key_to_pem,
    public_key_to_pem,
    verify_hitl_token,
)

__all__ = [
    # audit
    "GENESIS_PREV_HASH",
    "AuditEvent",
    "AuditFailure",
    "AuditRecord",
    "ChainVerification",
    "CommandInjectionAttempt",
    "CommandInjectionAttempt",
    # profiles
    "ConfigBundle",
    "ConfigUnavailable",
    "ConfigUnavailable",
    "DefaultDenied",
    "DefaultDenied",
    # enums
    "DenyReasonCode",
    # enums
    "DenyReasonCode",
    "EgressBlocked",
    "EgressBlocked",
    "HITLRule",
    # tokens
    "HITLTokenClaims",
    "IdentityUnresolved",
    "IdentityUnresolved",
    "InMemoryNonceStore",
    "IngressSource",
    "IngressSource",
    # intent
    "Intent",
    # decision
    "LayerDecision",
    # decision
    "LayerDecision",
    "LayerName",
    "LayerName",
    # errors
    "MLPEFError",
    # errors
    "MLPEFError",
    "NonceStore",
    "OutputFilterPolicy",
    "PIILeakDetected",
    "PIILeakDetected",
    "PathTraversalAttempt",
    "PathTraversalAttempt",
    # timing
    "PhaseTimings",
    "PipelineResult",
    "PipelineResult",
    "PipelineTimeout",
    "PolicyDenied",
    "PolicyDenied",
    "PolicyProfile",
    "Provenance",
    "ResourceKind",
    "ResourceLimitExceeded",
    "ResourceLimitExceeded",
    "ResourceScope",
    "SandboxError",
    "SandboxError",
    "SandboxLimits",
    "SandboxTimeout",
    "SandboxTimeout",
    "SecretLeakDetected",
    "SecretLeakDetected",
    "Severity",
    "Severity",
    "Stopwatch",
    "TokenError",
    "TokenError",
    "TokenExpired",
    "TokenExpired",
    "TokenInvalidSignature",
    "TokenInvalidSignature",
    "TokenMalformed",
    "TokenMalformed",
    "TokenNotYetValid",
    "TokenNotYetValid",
    "TokenReplay",
    "TokenReplay",
    "TokenScopeMismatch",
    "TokenScopeMismatch",
    "UnknownTool",
    "UnknownTool",
    "ValidationFailure",
    "ValidationFailure",
    "Verdict",
    "Verdict",
    "build_audit_event",
    "compute_record_hash",
    "default_locked_down_profile",
    "generate_keypair",
    "load_private_key_pem",
    "load_public_key_pem",
    "mint_hitl_token",
    "monotonic_ms",
    "now_epoch",
    "private_key_to_pem",
    "public_key_to_pem",
    "seal_event",
    "verify_chain",
    "verify_hitl_token",
]
