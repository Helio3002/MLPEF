"""The normalized `Intent` — the single shape every ingress adapter produces.

MCP, OpenAI-compatible, REST, and SDK-shim adapters all translate their native
request into an `Intent` and hand it to the identical five-layer pipeline. An
`Intent` is the *subject* of a security decision; it is never itself trusted to
make one. Nothing the LLM emits is a control signal — it is data to be validated.

`Intent` is frozen and forbids unknown fields so a malformed or padded request is
rejected at construction rather than silently carrying attacker-controlled extras
into later layers.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .enums import IngressSource


class Provenance(BaseModel):
    """Prior-step context for an agent's multi-step run.

    Layer 2 may use provenance as ABAC context (e.g. "this step followed an
    untrusted web fetch"). It is recorded data, not a trust assertion.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    parent_intent_id: str | None = None
    step_index: int = 0
    prior_tool: str | None = None


class Intent(BaseModel):
    """A single attempted tool call, normalized across all ingress adapters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"

    # Correlation ID assigned by ingress; threads this call through all five
    # layer decisions and the audit record.
    intent_id: str

    # Resolved by identity stage from the agent credential (never self-asserted
    # by the model). Drives which PolicyProfile applies.
    agent_id: str
    tenant: str

    tool: str  # registered tool name (validated against the profile allowlist)
    action: str  # logical action, e.g. "fs.read", "shell.exec", "http.get"
    resource: str  # target resource, e.g. a path or URL

    # Tool arguments as received. Validated against the per-tool Pydantic schema
    # in Layer 1; typed as JSON here because the shape is tool-specific.
    arguments: dict[str, JsonValue] = Field(default_factory=dict)

    ingress: IngressSource

    # Wall-clock seconds when ingress accepted the request. Audit metadata only;
    # not a security input (see deterministic-core rule).
    received_at: int

    # Present when the agent is retrying an action that required HITL approval.
    approval_token: str | None = None

    provenance: Provenance | None = None
