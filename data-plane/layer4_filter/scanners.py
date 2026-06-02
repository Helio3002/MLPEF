"""Layer 4 secret + PII scanners (deterministic: regex + Shannon entropy).

Defense-in-depth, **not** full DLP. Pattern + entropy scanning has false negatives
(novel secret formats slip through) and false positives (high-entropy data such as
hashes can be over-redacted). Both are logged as residual risk in THREAT_MODEL.md
(R-4, R-27). Output is scanned before it is returned to the agent.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_PII = "[REDACTED_PII]"


@dataclass(frozen=True)
class Finding:
    category: str  # "secret" | "pii" | "injection"
    kind: str
    count: int


_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_GITHUB_PAT = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*"
    r"['\"]?[A-Za-z0-9/_\-+=]{12,}"
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", _AWS_ACCESS_KEY),
    ("github_token", _GITHUB_TOKEN),
    ("github_pat", _GITHUB_PAT),
    ("slack_token", _SLACK_TOKEN),
    ("jwt", _JWT),
    ("private_key", _PRIVATE_KEY),
    ("assignment_secret", _ASSIGNMENT_SECRET),
)

# A run of credential-looking characters long enough to entropy-check.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9/_\-+=]{20,}")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    frequencies = (value.count(ch) for ch in set(value))
    return -sum((freq / length) * math.log2(freq / length) for freq in frequencies)


def scan_secrets(text: str, *, entropy_threshold: float) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    redacted = text
    for kind, pattern in _SECRET_PATTERNS:
        redacted, hits = pattern.subn(REDACTED_SECRET, redacted)
        if hits:
            findings.append(Finding("secret", kind, hits))

    high_entropy = 0

    def _maybe_redact(match: re.Match[str]) -> str:
        nonlocal high_entropy
        token = match.group(0)
        if _shannon_entropy(token) >= entropy_threshold:
            high_entropy += 1
            return REDACTED_SECRET
        return token

    redacted = _TOKEN_RUN.sub(_maybe_redact, redacted)
    if high_entropy:
        findings.append(Finding("secret", "high_entropy", high_entropy))
    return redacted, findings


_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}


def scan_pii(text: str, *, categories: Iterable[str]) -> tuple[str, list[Finding]]:
    # No categories configured => scan the full default set.
    selected = list(categories) or list(_PII_PATTERNS)
    findings: list[Finding] = []
    redacted = text
    for category in selected:
        pattern = _PII_PATTERNS.get(category)
        if pattern is None:
            continue
        redacted, hits = pattern.subn(REDACTED_PII, redacted)
        if hits:
            findings.append(Finding("pii", category, hits))
    return redacted, findings
