"""Listagem de achados com evidencias, para o painel e os relatorios."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import can_access, get_current_user, require_engagement_access
from app.db import get_session
from app.models import Engagement, Finding, User
from app.schemas import FindingOut

router = APIRouter(tags=["findings"])


@router.get("/engagements/{engagement_id}/findings", response_model=list[FindingOut])
async def list_findings(
    severity: str | None = None,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    stmt = (
        select(Finding)
        .where(Finding.engagement_id == eng.id)
        .options(selectinload(Finding.evidences))
        .order_by(Finding.confidence.desc())
    )
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = await session.scalars(stmt)
    return list(rows)


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Finding:
    stmt = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.evidences))
    )
    finding = await session.scalar(stmt)
    if finding is None:
        raise HTTPException(404, "Achado nao encontrado")
    eng = await session.get(Engagement, finding.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este achado")
    return finding
