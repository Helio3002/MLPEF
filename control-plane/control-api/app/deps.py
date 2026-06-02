"""FastAPI dependencies: DB session, admin session auth + RBAC, agent auth."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from . import crud, security
from .db import get_db
from .models import AdminUser, Agent


def get_current_admin(
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> AdminUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = authorization[len("bearer ") :].strip()
    admin = crud.get_admin_by_session(db, security.hash_session_token(token))
    if admin is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session")
    return admin


def require_roles(*roles: str) -> Callable[[AdminUser], AdminUser]:
    """Dependency factory enforcing that the caller holds one of `roles`."""
    allowed = set(roles)

    def checker(admin: Annotated[AdminUser, Depends(get_current_admin)]) -> AdminUser:
        if admin.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return admin

    return checker


def get_current_agent(
    db: Annotated[Session, Depends(get_db)],
    x_agent_key: Annotated[str | None, Header()] = None,
) -> Agent:
    """Authenticate the proxy/agent by its API key (for the config-bundle pull)."""
    if not x_agent_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing agent key")
    agent = crud.get_agent_by_credential(db, security.hash_api_key(x_agent_key))
    if agent is None or agent.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent credential")
    return agent
