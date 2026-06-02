"""Layer 5 — tamper-evident audit chain (shared, deterministic, framework-free).

Each audit record is hash-chained: its `record_hash` covers the record's content
*and* the previous record's hash, so altering, deleting, or reordering any record
breaks the chain and is detectable by `verify_chain`. This is **tamper-evident,
not tamper-proof** — it proves the log was modified, it does not prevent
modification (see the WORM note in THREAT_MODEL.md).

Split of responsibility:
  * `AuditEvent` is what an emitter produces — the full who/what/resource/decision
    /reason/timestamp/outcome plus the five-layer trace (correlation_id ties it to
    the intent). It carries no chain fields.
  * The audit *store* (control plane, single writer) assigns `seq` + `prev_hash`,
    stamps `recorded_at`, and `seal_event`s it into an `AuditRecord`. Sealing
    server-side keeps the chain consistent without distributed ordering.

Hashing is deterministic: canonical JSON (sorted keys, no whitespace) → SHA-256.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .decision import LayerDecision, PipelineResult
from .enums import DenyReasonCode, IngressSource, Verdict
from .intent import Intent

# 32 zero bytes (hex) — the prev_hash of the very first record in a chain.
GENESIS_PREV_HASH = "0" * 64


class AuditEvent(BaseModel):
    """The auditable facts about one intent's journey through the pipeline.

    SOC 2 / ISO 27001 fields: who (`agent_id`/`tenant`), what (`tool`/`action`),
    resource, decision (`final_verdict`), reason, timestamp, outcome — plus the
    full `layer_trace` so an investigator can see every layer's decision.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    correlation_id: str  # == Intent.intent_id; threads intent → layers → outcome
    timestamp: int  # epoch seconds when the decision was made
    tenant: str
    agent_id: str  # the actor (who)
    ingress: IngressSource
    tool: str
    action: str  # what
    resource: str
    final_verdict: Verdict  # decision / outcome
    reason_code: DenyReasonCode | None = None
    reason: str = ""
    security_event: bool = False
    layer_trace: list[LayerDecision] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """A sealed, chained audit entry as persisted by the store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int  # monotonic position in the chain (0-based)
    prev_hash: str  # record_hash of seq-1, or GENESIS_PREV_HASH for seq 0
    recorded_at: int  # epoch seconds when the store sealed it
    event: AuditEvent
    record_hash: str  # SHA-256 over {seq, prev_hash, recorded_at, event}


class ChainVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    records_checked: int
    first_broken_seq: int | None = None
    detail: str = ""


def _canonical_bytes(payload: dict[str, JsonValue]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_record_hash(
    *, seq: int, prev_hash: str, recorded_at: int, event: AuditEvent
) -> str:
    payload: dict[str, JsonValue] = {
        "seq": seq,
        "prev_hash": prev_hash,
        "recorded_at": recorded_at,
        "event": event.model_dump(mode="json"),
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def seal_event(
    event: AuditEvent, *, seq: int, prev_hash: str, recorded_at: int
) -> AuditRecord:
    """Chain an event into an immutable record by computing its hash."""
    record_hash = compute_record_hash(
        seq=seq, prev_hash=prev_hash, recorded_at=recorded_at, event=event
    )
    return AuditRecord(
        seq=seq,
        prev_hash=prev_hash,
        recorded_at=recorded_at,
        event=event,
        record_hash=record_hash,
    )


def build_audit_event(
    intent: Intent, result: PipelineResult, *, timestamp: int
) -> AuditEvent:
    """Assemble the audit event for a completed pipeline run."""
    return AuditEvent(
        correlation_id=intent.intent_id,
        timestamp=timestamp,
        tenant=intent.tenant,
        agent_id=intent.agent_id,
        ingress=intent.ingress,
        tool=intent.tool,
        action=intent.action,
        resource=intent.resource,
        final_verdict=result.final_verdict,
        reason_code=result.reason_code,
        reason=result.reason,
        security_event=result.security_event,
        layer_trace=list(result.layer_decisions),
    )


def verify_chain(records: Sequence[AuditRecord]) -> ChainVerification:
    """Recompute the chain and report the first break, if any.

    `records` must be ordered by ascending `seq`. Detects: altered content (hash
    mismatch), a broken prev→hash link (deletion/reordering/insertion), and a bad
    genesis link.
    """
    prev = GENESIS_PREV_HASH
    checked = 0
    for record in records:
        if record.prev_hash != prev:
            return ChainVerification(
                ok=False,
                records_checked=checked,
                first_broken_seq=record.seq,
                detail=f"prev_hash linkage broken at seq {record.seq}",
            )
        expected = compute_record_hash(
            seq=record.seq,
            prev_hash=record.prev_hash,
            recorded_at=record.recorded_at,
            event=record.event,
        )
        if expected != record.record_hash:
            return ChainVerification(
                ok=False,
                records_checked=checked,
                first_broken_seq=record.seq,
                detail=f"record_hash mismatch at seq {record.seq} (content altered)",
            )
        prev = record.record_hash
        checked += 1
    return ChainVerification(ok=True, records_checked=checked, detail="chain intact")
