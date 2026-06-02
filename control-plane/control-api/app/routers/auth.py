"""Admin authentication: password login issues a session bearer token."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import crud, security
from ..db import get_db
from ..deps import get_current_admin
from ..models import AdminUser
from ..schemas import AdminOut, LoginIn, LoginOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, db: Annotated[Session, Depends(get_db)]) -> LoginOut:
    admin = crud.get_admin_by_username(db, body.username)
    if admin is None or not security.verify_password(body.password, admin.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    token, expires_at = crud.create_session(db, admin)
    return LoginOut(token=token, role=admin.role, expires_at=expires_at)


@router.get("/me", response_model=AdminOut)
def me(admin: Annotated[AdminUser, Depends(get_current_admin)]) -> AdminUser:
    return admin
