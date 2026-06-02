"""Audit endpoints: ingestion (agent-authenticated), querying, and chain verify.

Ingestion is authenticated with the agent API key (the proxy emits on the agent's
behalf — proxy-level auth replaces this in Phase 8). Querying and verification
require an authenticated admin. The chain is sealed server-side on append.
"""

from __future__ import annotations

from typing import Annotated

from common import AuditEvent, AuditRecord, ChainVerification
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import crud
from ..db import get_db
from ..deps import get_current_admin, get_current_agent
from ..models import AdminUser, Agent

router = APIRouter(prefix="/audit", tags=["audit"])


@router.post("", response_model=AuditRecord, status_code=status.HTTP_201_CREATED)
def ingest(
    event: AuditEvent,
    db: Annotated[Session, Depends(get_db)],
    agent: Annotated[Agent, Depends(get_current_agent)],
) -> AuditRecord:
    if event.agent_id != agent.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "event agent_id does not match the presented credential"
        )
    return crud.append_audit_event(db, event)


@router.get("", response_model=list[AuditRecord])
def list_records(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
    agent_id: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    correlation_id: str | None = None,
    security_event: bool | None = None,
    limit: int = 100,
) -> list[AuditRecord]:
    return crud.list_audit(
        db,
        agent_id=agent_id,
        action=action,
        outcome=outcome,
        correlation_id=correlation_id,
        security_event=security_event,
        limit=limit,
    )


@router.get("/verify", response_model=ChainVerification)
def verify(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> ChainVerification:
    return crud.verify_audit_chain(db)
