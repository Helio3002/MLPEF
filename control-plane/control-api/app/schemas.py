"""Request/response models for the control-api.

The rich policy shape is the shared `common.PolicyProfile` — profiles are created
and returned as that exact type, so the control plane and the proxy never drift.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from common import PolicyProfile
from pydantic import BaseModel, ConfigDict, Field, JsonValue

Role = Literal["superadmin", "security-reviewer", "approver", "read-only"]


class LoginIn(BaseModel):
    username: str
    password: str


class LoginOut(BaseModel):
    token: str
    role: Role
    expires_at: datetime


class AdminOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: Role


class AgentCreate(BaseModel):
    """Register an agent with just a name (+ optional tenant/profile).

    If `profile_id` is omitted the agent is assigned the deny-most default
    profile, so an unconfigured agent is still locked down.
    """

    name: str
    tenant: str = "default"
    profile_id: str | None = None


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    tenant: str
    profile_id: str
    status: str
    created_at: datetime
    updated_at: datetime


class AgentCredentialOut(AgentOut):
    """Returned only once, at registration — carries the plaintext API key."""

    api_key: str


class AssignProfileIn(BaseModel):
    profile_id: str


class ProfileOut(BaseModel):
    profile: PolicyProfile
    agents_affected: int
    updated_at: datetime


class ProfileImpact(BaseModel):
    profile_id: str
    agents_affected: int


class ToolIn(BaseModel):
    name: str
    json_schema: dict[str, JsonValue] = Field(default_factory=dict)
    default_allow: bool = False


class ToolOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    json_schema: dict[str, JsonValue]
    default_allow: bool
