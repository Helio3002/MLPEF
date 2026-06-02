"""Decision types — the output side of every layer and of the whole pipeline.

A `LayerDecision` is what each of the five layers returns. A `PipelineResult`
aggregates the per-layer trace into the final outcome that Layer 5 audits. The
constructors enforce the fail-closed contract: a deny must carry a stable
`DenyReasonCode`, and `from_error` turns *any* `MLPEFError` into a correctly-coded
deny so an exception can never leak through as an allow.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .enums import DenyReasonCode, LayerName, Verdict
from .errors import MLPEFError


class LayerDecision(BaseModel):
    """The verdict produced by a single layer for a single intent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    layer: LayerName
    verdict: Verdict
    reason_code: DenyReasonCode | None = None
    reason: str = ""
    security_event: bool = False
    elapsed_ms: float = 0.0
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @classmethod
    def allow(
        cls,
        layer: LayerName,
        *,
        reason: str = "",
        elapsed_ms: float = 0.0,
        metadata: dict[str, JsonValue] | None = None,
    ) -> LayerDecision:
        return cls(
            layer=layer,
            verdict=Verdict.ALLOW,
            reason=reason,
            elapsed_ms=elapsed_ms,
            metadata=metadata or {},
        )

    @classmethod
    def deny(
        cls,
        layer: LayerName,
        reason_code: DenyReasonCode,
        reason: str,
        *,
        security_event: bool = False,
        elapsed_ms: float = 0.0,
        metadata: dict[str, JsonValue] | None = None,
    ) -> LayerDecision:
        return cls(
            layer=layer,
            verdict=Verdict.DENY,
            reason_code=reason_code,
            reason=reason,
            security_event=security_event,
            elapsed_ms=elapsed_ms,
            metadata=metadata or {},
        )

    @classmethod
    def hitl_required(
        cls,
        layer: LayerName,
        reason: str,
        *,
        elapsed_ms: float = 0.0,
        metadata: dict[str, JsonValue] | None = None,
    ) -> LayerDecision:
        return cls(
            layer=layer,
            verdict=Verdict.HITL_REQUIRED,
            reason_code=DenyReasonCode.HITL_REQUIRED,
            reason=reason,
            elapsed_ms=elapsed_ms,
            metadata=metadata or {},
        )

    @classmethod
    def from_error(cls, error: MLPEFError, *, elapsed_ms: float = 0.0) -> LayerDecision:
        """Convert any fail-closed `MLPEFError` into a coded deny decision."""
        return cls(
            layer=error.layer,
            verdict=Verdict.DENY,
            reason_code=error.reason_code,
            reason=error.message,
            security_event=error.security_event,
            elapsed_ms=elapsed_ms,
            metadata=error.detail,
        )


class PipelineResult(BaseModel):
    """The final outcome plus the full five-layer trace for one intent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    intent_id: str
    final_verdict: Verdict
    reason_code: DenyReasonCode | None = None
    reason: str = ""
    security_event: bool = False
    layer_decisions: list[LayerDecision] = Field(default_factory=list)
    completed_at: int = 0

    @property
    def allowed(self) -> bool:
        return self.final_verdict is Verdict.ALLOW

    @property
    def total_elapsed_ms(self) -> float:
        return sum(d.elapsed_ms for d in self.layer_decisions)

    @classmethod
    def from_layers(
        cls,
        intent_id: str,
        layer_decisions: list[LayerDecision],
        *,
        completed_at: int = 0,
    ) -> PipelineResult:
        """Derive the final outcome from an ordered list of layer decisions.

        The first non-allow decision determines the outcome (layers run in order
        and stop on the first failure); if every layer allowed, the result is
        allow. A `security_event` anywhere in the trace propagates to the result.
        """
        deciding = next(
            (d for d in layer_decisions if d.verdict is not Verdict.ALLOW),
            None,
        )
        security_event = any(d.security_event for d in layer_decisions)
        if deciding is None:
            return cls(
                intent_id=intent_id,
                final_verdict=Verdict.ALLOW,
                layer_decisions=layer_decisions,
                security_event=security_event,
                completed_at=completed_at,
            )
        return cls(
            intent_id=intent_id,
            final_verdict=deciding.verdict,
            reason_code=deciding.reason_code,
            reason=deciding.reason,
            security_event=security_event,
            layer_decisions=layer_decisions,
            completed_at=completed_at,
        )
