"""Modelo de dados. Tudo gira em torno de Engagement (cliente + escopo + autorizacao)."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    paused = "paused"


class User(Base):
    """Usuario do sistema. Senha guardada apenas como hash."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, default="")
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, default="analyst")  # admin | analyst
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Engagement(Base):
    """Um trabalho para um cliente. Carrega o escopo e a autorizacao assinada."""

    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    # Consultor dono deste cliente (multi-tenant). Admin ve todos.
    owner_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    client_name: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    # Escopo autorizado: lista de hosts, IPs, CIDRs e dominios.
    scope: Mapped[list] = mapped_column(JSON, default=list)
    # Gate de autorizacao: sem isso, nenhum scan roda.
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_by: Mapped[str | None] = mapped_column(String, nullable=True)
    # Opt-in para sondas intrusivas (ativas, nao-destrutivas). Padrao: desligado.
    allow_intrusive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list[ScanJob]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class ScanJob(Base):
    """Uma execucao de coleta. Roda em background no worker."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"))
    targets: Mapped[list] = mapped_column(JSON, default=list)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    collectors: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.queued
    )
    # Progresso para acompanhamento em tempo real.
    progress: Mapped[int] = mapped_column(Integer, default=0)   # 0..100
    phase: Mapped[str] = mapped_column(String, default="")      # etapa atual
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(String, default="")    # resumo (ex: "4 subdominios")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    pause_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    engagement: Mapped[Engagement] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Um achado. Sempre ligado a uma evidencia e a uma avaliacao da IA."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"))
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"))

    target: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str | None] = mapped_column(String, nullable=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)

    # Saida da camada de IA (raciocinio sobre os fatos).
    ai_assessment: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Confianca 0..1 do achado, para o analista filtrar ruido.
    confidence: Mapped[float] = mapped_column(Float, default=0.5)

    # Deduplicacao/persistencia entre scans.
    signature: Mapped[str] = mapped_column(String, index=True, default="")
    times_seen: Mapped[int] = mapped_column(Integer, default=1)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    scan: Mapped[ScanJob | None] = relationship(back_populates="findings")
    evidences: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    """Prova bruta e imutavel de um achado. Nunca e regerada pela IA."""

    __tablename__ = "evidences"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"))
    kind: Mapped[str] = mapped_column(String, default="raw")  # raw | http | screenshot
    # Conteudo curto inline; blobs grandes vao pro S3 e guardamos a chave.
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    s3_key: Mapped[str | None] = mapped_column(String, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[Finding] = relationship(back_populates="evidences")
