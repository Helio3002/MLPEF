"""HITL approval queue + token minting.

The agent's proxy (agent-key auth) opens approval requests when Layer 2 returns
HITL_REQUIRED. Approvers act on the queue: approving mints a scoped, single-use,
expiring Ed25519 token (signed by the control plane) that the proxy verifies at
Layer 2; denying closes the request. The public key is served for verification.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .. import crud, signing
from ..db import get_db
from ..deps import get_current_admin, get_current_agent, require_roles
from ..models import AdminUser, Agent
from ..schemas import HITLApprovalOut, HITLRequestCreate, HITLRequestOut, PublicKeyOut

router = APIRouter(prefix="/hitl", tags=["hitl"])

_APPROVE_ROLES = ("superadmin", "approver")


@router.get("/public-key", response_model=PublicKeyOut)
def public_key() -> PublicKeyOut:
    # Intentionally PUBLIC (no auth): this is the Ed25519 *public* verification key.
    # The proxy fetches it at startup before it holds any agent credential, and a
    # public key is safe to disclose — only the control plane holds the private key
    # that mints tokens (see THREAT_MODEL.md R-8 / assume-breach: proxy verifies,
    # never mints). Making it public removes a needless bootstrap dependency.
    return PublicKeyOut(algorithm="ed25519", public_key_pem=signing.public_key_pem())


@router.post("/requests", response_model=HITLRequestOut, status_code=status.HTTP_201_CREATED)
def create_request(
    body: HITLRequestCreate,
    db: Annotated[Session, Depends(get_db)],
    agent: Annotated[Agent, Depends(get_current_agent)],
) -> HITLRequestOut:
    # The subject is the authenticated agent — never taken from the body.
    request = crud.create_hitl_request(
        db, agent_id=agent.id, tenant=agent.tenant, action=body.action, resource=body.resource
    )
    return HITLRequestOut.model_validate(request)


@router.get("/requests", response_model=list[HITLRequestOut])
def list_requests(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> list[HITLRequestOut]:
    rows = crud.list_hitl_requests(db, status=status_filter)
    return [HITLRequestOut.model_validate(row) for row in rows]


@router.post("/requests/{request_id}/approve", response_model=HITLApprovalOut)
def approve_request(
    request_id: str,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[AdminUser, Depends(require_roles(*_APPROVE_ROLES))],
) -> HITLApprovalOut:
    request = crud.get_hitl_request(db, request_id)
    if request is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "request not found")
    if request.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"request already {request.status}")
    token, expires_at = crud.approve_hitl_request(
        db, request, approver_id=admin.id, private_key=signing.signing_key()
    )
    return HITLApprovalOut(hitl_request_id=request.id, token=token, expires_at=expires_at)


@router.post("/requests/{request_id}/deny", response_model=HITLRequestOut)
def deny_request(
    request_id: str,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[AdminUser, Depends(require_roles(*_APPROVE_ROLES))],
) -> HITLRequestOut:
    request = crud.get_hitl_request(db, request_id)
    if request is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "request not found")
    if request.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"request already {request.status}")
    crud.deny_hitl_request(db, request, approver_id=admin.id)
    return HITLRequestOut.model_validate(request)
