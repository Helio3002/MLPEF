"""The five-layer enforcement pipeline (fail-closed, unskippable audit).

`process` runs L1 Validate -> L2 Policy -> L3 Sandbox -> L4 Filter, stopping at the
first non-allow, then ALWAYS records an audit entry (L5). Any exception or timeout
becomes a deny `LayerDecision` rather than escaping. If the audit write itself
fails, the whole call fails closed (deny, no output) even if the layers allowed.

Only tools that execute code run in the sandbox; `default_command_builder` maps
`shell.exec` to its argv and returns None for everything else (L3/L4 skipped).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common import (
    AuditFailure,
    DenyReasonCode,
    Intent,
    LayerDecision,
    LayerName,
    MLPEFError,
    NonceStore,
    PipelineResult,
    PolicyProfile,
    Verdict,
    now_epoch,
)
from layer1_validation import ToolSpec
from layer1_validation import validate as l1_validate
from layer2_policy import evaluate as l2_evaluate
from layer3_sandbox import WarmPool
from layer3_sandbox import execute as l3_execute
from layer4_filter import filter_output as l4_filter
from layer5_audit import Auditor

CommandBuilder = Callable[[Intent], list[str] | None]


@dataclass(frozen=True)
class PipelineOutcome:
    result: PipelineResult
    output: str


def default_command_builder(intent: Intent) -> list[str] | None:
    """Map an intent to a sandbox argv. Only shell.exec executes code; other
    reference tools return None (no sandbox run)."""
    if intent.tool == "shell.exec":
        argv = intent.arguments.get("argv")
        if isinstance(argv, list):
            return [str(item) for item in argv]
    return None


class Pipeline:
    def __init__(
        self,
        *,
        public_key: Ed25519PublicKey,
        nonce_store: NonceStore,
        sandbox_pool: WarmPool,
        auditor: Auditor,
        command_builder: CommandBuilder = default_command_builder,
        tool_specs: dict[str, ToolSpec] | None = None,
        leeway_seconds: int = 0,
    ) -> None:
        self._public_key = public_key
        self._nonce_store = nonce_store
        self._pool = sandbox_pool
        self._auditor = auditor
        self._command_builder = command_builder
        self._tool_specs = tool_specs
        self._leeway = leeway_seconds

    def process(self, intent: Intent, profile: PolicyProfile) -> PipelineOutcome:
        decisions: list[LayerDecision] = []
        output = ""
        try:
            output = self._run_layers(intent, profile, decisions)
        except MLPEFError as exc:
            decisions.append(LayerDecision.from_error(exc))
            output = ""
        except Exception:
            decisions.append(
                LayerDecision.deny(
                    LayerName.PIPELINE,
                    DenyReasonCode.INTERNAL_ERROR,
                    "unexpected pipeline error",
                )
            )
            output = ""
        return self._finalize(intent, decisions, output)

    def _run_layers(
        self, intent: Intent, profile: PolicyProfile, decisions: list[LayerDecision]
    ) -> str:
        d1 = l1_validate(intent, profile, specs=self._tool_specs)
        decisions.append(d1)
        if d1.verdict is not Verdict.ALLOW:
            return ""

        d2 = l2_evaluate(
            intent,
            profile,
            public_key=self._public_key,
            nonce_store=self._nonce_store,
            now=now_epoch(),
            leeway_seconds=self._leeway,
        )
        decisions.append(d2)
        if d2.verdict is not Verdict.ALLOW:
            return ""

        argv = self._command_builder(intent)
        if argv is None:
            return ""  # tool does not execute code in the sandbox

        d3, sandbox_result = l3_execute(
            self._pool, argv, timeout_seconds=profile.sandbox_limits.timeout_seconds
        )
        decisions.append(d3)
        if d3.verdict is not Verdict.ALLOW or sandbox_result is None:
            return ""

        d4, filtered = l4_filter(sandbox_result.stdout, profile.output_filter)
        decisions.append(d4)
        if d4.verdict is not Verdict.ALLOW:
            return ""
        return filtered.sanitized

    def _finalize(
        self, intent: Intent, decisions: list[LayerDecision], output: str
    ) -> PipelineOutcome:
        result = PipelineResult.from_layers(intent.intent_id, decisions, completed_at=now_epoch())
        try:
            self._auditor.record(intent, result)
        except Exception:
            # Unskippable audit failed -> fail closed regardless of layer verdicts.
            decisions.append(
                LayerDecision.from_error(AuditFailure("audit write failed; failing closed"))
            )
            result = PipelineResult.from_layers(
                intent.intent_id, decisions, completed_at=now_epoch()
            )
            return PipelineOutcome(result=result, output="")
        return PipelineOutcome(result=result, output=output if result.allowed else "")

    def deny_and_audit(self, intent: Intent, decision: LayerDecision) -> PipelineOutcome:
        """Record a single-decision denial (e.g. identity failure) and return it."""
        result = PipelineResult.from_layers(intent.intent_id, [decision], completed_at=now_epoch())
        with contextlib.suppress(Exception):
            self._auditor.record(intent, result)
        return PipelineOutcome(result=result, output="")
