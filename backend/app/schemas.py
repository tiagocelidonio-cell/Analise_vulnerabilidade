"""Schemas de entrada/saida da API (Pydantic v2)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: str
    name: str = ""
    password: str
    role: str = "analyst"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    name: str
    role: str
    is_active: bool


class EngagementCreate(BaseModel):
    client_name: str
    name: str
    scope: list[str] = Field(default_factory=list)
    authorized: bool = False
    authorized_by: str | None = None
    allow_intrusive: bool = False


class EngagementUpdate(BaseModel):
    client_name: str | None = None
    name: str | None = None
    scope: list[str] | None = None
    authorized: bool | None = None
    authorized_by: str | None = None
    allow_intrusive: bool | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_name: str
    name: str
    scope: list[str]
    authorized: bool
    authorized_by: str | None
    allow_intrusive: bool
    created_at: datetime


class ScanCreate(BaseModel):
    targets: list[str]
    ports: list[int] = Field(default_factory=list)
    collectors: list[str] = Field(default_factory=list)  # vazio = todos os padrao


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    targets: list[str]
    ports: list[int]
    collectors: list[str]
    status: str
    error: str | None
    created_at: datetime
    finished_at: datetime | None


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    kind: str
    content: str | None
    s3_key: str | None
    collected_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target: str
    port: int | None
    service: str | None
    title: str
    description: str | None
    severity: str
    cvss: float | None
    epss: float | None
    in_kev: bool
    cve_ids: list[str]
    ai_assessment: dict | None
    confidence: float
    created_at: datetime
    evidences: list[EvidenceOut] = Field(default_factory=list)
