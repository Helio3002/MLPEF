"""Policy-profile CRUD. Editing a profile reconfigures every agent on it, so
mutating endpoints expose the affected-agent count (the UI shows it before save).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from common import PolicyProfile

from .. import crud
from ..db import get_db
from ..deps import get_current_admin, require_roles
from ..models import AdminUser
from ..schemas import ProfileImpact, ProfileOut

router = APIRouter(prefix="/profiles", tags=["profiles"])

_WRITE_ROLES = ("superadmin", "security-reviewer")


def _to_out(db: Session, profile: PolicyProfile) -> ProfileOut:
    row = crud.get_profile_row(db, profile.profile_id)
    affected = crud.count_agents_on_profile(db, profile.profile_id)
    updated_at = row.updated_at if row is not None else datetime.now(timezone.utc)
    return ProfileOut(profile=profile, agents_affected=affected, updated_at=updated_at)


@router.get("", response_model=list[PolicyProfile])
def list_profiles(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
    tenant: str | None = None,
) -> list[PolicyProfile]:
    return [PolicyProfile.model_validate(r.definition) for r in crud.list_profiles(db, tenant)]


@router.get("/{profile_id}", response_model=ProfileOut)
def get_profile(
    profile_id: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> ProfileOut:
    profile = crud.get_profile(db, profile_id)
    if profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    return _to_out(db, profile)


@router.get("/{profile_id}/impact", response_model=ProfileImpact)
def profile_impact(
    profile_id: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> ProfileImpact:
    if crud.get_profile_row(db, profile_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    return ProfileImpact(
        profile_id=profile_id,
        agents_affected=crud.count_agents_on_profile(db, profile_id),
    )


@router.post("", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile(
    body: PolicyProfile,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> ProfileOut:
    if crud.get_profile_row(db, body.profile_id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "profile_id already exists")
    crud.create_profile(db, body)
    return _to_out(db, body)


@router.put("/{profile_id}", response_model=ProfileOut)
def update_profile(
    profile_id: str,
    body: PolicyProfile,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> ProfileOut:
    if body.profile_id != profile_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "profile_id in body must match path")
    row = crud.get_profile_row(db, profile_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    crud.update_profile(db, row, body)
    return _to_out(db, body)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(
    profile_id: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles("superadmin"))],
) -> None:
    row = crud.get_profile_row(db, profile_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    in_use = crud.count_agents_on_profile(db, profile_id)
    if in_use > 0:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"profile in use by {in_use} agent(s); reassign first"
        )
    crud.delete_profile(db, row)
