"""Layer 4 orchestration: scan -> redact -> neutralize, fail-closed.

Layer 4 sanitizes the tool output that returns to the agent. Detected secrets and
injection markers are recorded as a `security_event` (the redacted text is still
returned — the action already executed in L3). If a scanner errors, the layer
fails closed: deny and return empty output rather than leak unfiltered content.
A future quarantine mode could deny outright on secrets (OUTPUT_SECRET_DETECTED).
"""

from __future__ import annotations

from dataclasses import dataclass

from common import DenyReasonCode, LayerDecision, LayerName, Stopwatch, Verdict
from common.profiles import OutputFilterPolicy

from .injection import neutralize_injection
from .scanners import Finding, scan_pii, scan_secrets


@dataclass(frozen=True)
class FilterResult:
    sanitized: str
    findings: list[Finding]

    def count(self, category: str) -> int:
        return sum(f.count for f in self.findings if f.category == category)


def _filter(text: str, policy: OutputFilterPolicy) -> tuple[LayerDecision, FilterResult]:
    findings: list[Finding] = []
    sanitized = text

    if policy.scan_secrets:
        sanitized, found = scan_secrets(
            sanitized, entropy_threshold=policy.secret_entropy_threshold
        )
        findings.extend(found)
    if policy.redact_pii:
        sanitized, found = scan_pii(sanitized, categories=policy.pii_categories)
        findings.extend(found)
    if policy.neutralize_injection:
        sanitized, found = neutralize_injection(sanitized)
        findings.extend(found)

    # Secrets and injection in output are suspicious; PII redaction alone is not.
    security_event = any(f.category in ("secret", "injection") for f in findings)
    decision = LayerDecision(
        layer=LayerName.L4_FILTER,
        verdict=Verdict.ALLOW,
        reason="output sanitized" if findings else "no findings",
        security_event=security_event,
        metadata={
            "secret_findings": sum(f.count for f in findings if f.category == "secret"),
            "pii_findings": sum(f.count for f in findings if f.category == "pii"),
            "injection_findings": sum(f.count for f in findings if f.category == "injection"),
        },
    )
    return decision, FilterResult(sanitized=sanitized, findings=findings)


def filter_output(text: str, policy: OutputFilterPolicy) -> tuple[LayerDecision, FilterResult]:
    with Stopwatch() as stopwatch:
        try:
            decision, result = _filter(text, policy)
        except Exception:
            # Fail closed: never return unfiltered output if a scanner errored.
            decision = LayerDecision.deny(
                LayerName.L4_FILTER, DenyReasonCode.INTERNAL_ERROR, "output filtering failed"
            )
            result = FilterResult(sanitized="", findings=[])
    return decision.model_copy(update={"elapsed_ms": stopwatch.elapsed_ms}), result
