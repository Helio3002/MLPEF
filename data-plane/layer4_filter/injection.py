"""Neutralize tool output that resembles instructions to the agent.

Output is untrusted DATA, never a control channel. This strips common
prompt-injection markers; it is heuristic (false negatives expected, R-26). The
real guarantee is upstream: every subsequent tool call still passes the L1
allowlist + L2 default-deny regardless of what an injected string says.
"""

from __future__ import annotations

import re

from .scanners import Finding

_NEUTRALIZED = "[NEUTRALIZED]"

_IGNORE_PREVIOUS = re.compile(
    r"(?i)\b(?:ignore|disregard|forget)\b[^\n]{0,30}?"
    r"\b(?:previous|prior|preceding|above|earlier|all)\b[^\n]{0,20}?"
    r"\b(?:instructions?|prompts?|messages?|context)\b"
)
_ROLE_MARKER = re.compile(r"(?im)^\s*(?:system|assistant|developer)\s*:")
_NEW_INSTRUCTIONS = re.compile(r"(?i)\bnew\s+instructions?\s*:")
_TAG_INJECTION = re.compile(r"(?i)</?\s*(?:system|assistant|tool|instructions?)\s*>")

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", _IGNORE_PREVIOUS),
    ("role_marker", _ROLE_MARKER),
    ("new_instructions", _NEW_INSTRUCTIONS),
    ("tag_injection", _TAG_INJECTION),
)


def neutralize_injection(text: str) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    sanitized = text
    for kind, pattern in _INJECTION_PATTERNS:
        sanitized, hits = pattern.subn(_NEUTRALIZED, sanitized)
        if hits:
            findings.append(Finding("injection", kind, hits))
    return sanitized, findings
