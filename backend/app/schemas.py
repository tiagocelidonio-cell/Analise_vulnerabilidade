"""Schemas de entrada/saida da API (Pydantic v2)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EngagementCreate(BaseModel):
    client_name: str
    name: str
    scope: list[str] = Field(default_factory=list)
    authorized: bool = False
    authorized_by: str | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_name: str
    name: str
    scope: list[str]
    authorized: bool
    authorized_by: str | None
    created_at: datetime


class ScanCreate(BaseModel):
    targets: list[str]
    ports: list[int] = Field(default_factory=list)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    targets: list[str]
    ports: list[int]
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
