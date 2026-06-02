"""Agent registration, lifecycle, profile assignment, and the config-bundle pull.

Registration takes name (+ optional tenant/profile) only and returns a generated
API key exactly once. If no profile is given, the deny-most default is assigned,
so an unconfigured agent is still locked down.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from common import ConfigBundle

from .. import crud, security
from ..db import get_db
from ..deps import get_current_admin, get_current_agent, require_roles
from ..models import AdminUser, Agent
from ..schemas import AgentCreate, AgentCredentialOut, AgentOut, AssignProfileIn

router = APIRouter(prefix="/agents", tags=["agents"])

_DEFAULT_PROFILE_ID = "default-locked-down"
_WRITE_ROLES = ("superadmin", "security-reviewer")


@router.post("", response_model=AgentCredentialOut, status_code=status.HTTP_201_CREATED)
def register_agent(
    body: AgentCreate,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> AgentCredentialOut:
    profile_id = body.profile_id or _DEFAULT_PROFILE_ID
    if crud.get_profile_row(db, profile_id) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown profile_id: {profile_id}")
    api_key = security.generate_api_key()
    agent = crud.create_agent(
        db,
        name=body.name,
        tenant=body.tenant,
        profile_id=profile_id,
        credential_hash=security.hash_api_key(api_key),
    )
    return AgentCredentialOut(
        id=agent.id,
        name=agent.name,
        tenant=agent.tenant,
        profile_id=agent.profile_id,
        status=agent.status,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
        api_key=api_key,
    )


@router.get("", response_model=list[AgentOut])
def list_agents(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
    tenant: str | None = None,
) -> list[Agent]:
    return crud.list_agents(db, tenant)


@router.get("/{agent_id}", response_model=AgentOut)
def get_agent(
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> Agent:
    agent = crud.get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    return agent


@router.post("/{agent_id}/suspend", response_model=AgentOut)
def suspend_agent(
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> Agent:
    agent = crud.get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    agent.status = "suspended"
    return crud.save_agent(db, agent)


@router.post("/{agent_id}/activate", response_model=AgentOut)
def activate_agent(
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> Agent:
    agent = crud.get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    agent.status = "active"
    return crud.save_agent(db, agent)


@router.post("/{agent_id}/profile", response_model=AgentOut)
def assign_profile(
    agent_id: str,
    body: AssignProfileIn,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> Agent:
    agent = crud.get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    if crud.get_profile_row(db, body.profile_id) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown profile_id: {body.profile_id}")
    agent.profile_id = body.profile_id
    return crud.save_agent(db, agent)


@router.get("/{agent_id}/config-bundle", response_model=ConfigBundle)
def config_bundle(
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    agent: Annotated[Agent, Depends(get_current_agent)],
) -> ConfigBundle:
    # The agent authenticates with its own API key; it may only pull its own bundle.
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "agent key does not match this agent")
    bundle = crud.build_config_bundle(db, agent)
    if bundle is None:
        # Fail closed: a missing profile is an error, not an allow-all.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no profile resolved for agent")
    return bundle
