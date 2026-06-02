"""Tool / schema registry CRUD."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import crud
from ..db import get_db
from ..deps import get_current_admin, require_roles
from ..models import AdminUser, Tool
from ..schemas import ToolIn, ToolOut

router = APIRouter(prefix="/tools", tags=["tools"])

_WRITE_ROLES = ("superadmin", "security-reviewer")


@router.get("", response_model=list[ToolOut])
def list_tools(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> list[Tool]:
    return crud.list_tools(db)


@router.get("/{name}", response_model=ToolOut)
def get_tool(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> Tool:
    tool = crud.get_tool(db, name)
    if tool is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tool not found")
    return tool


@router.put("/{name}", response_model=ToolOut)
def upsert_tool(
    name: str,
    body: ToolIn,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> Tool:
    return crud.upsert_tool(db, name, dict(body.json_schema), body.default_allow)


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tool(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[AdminUser, Depends(require_roles(*_WRITE_ROLES))],
) -> None:
    tool = crud.get_tool(db, name)
    if tool is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tool not found")
    crud.delete_tool(db, tool)
