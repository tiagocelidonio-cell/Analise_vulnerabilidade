"""Listagem de achados com evidencias, para o painel e os relatorios."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import get_session
from app.models import Finding
from app.schemas import FindingOut

router = APIRouter(tags=["findings"])


@router.get("/engagements/{engagement_id}/findings", response_model=list[FindingOut])
async def list_findings(
    engagement_id: str,
    severity: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    stmt = (
        select(Finding)
        .where(Finding.engagement_id == engagement_id)
        .options(selectinload(Finding.evidences))
        .order_by(Finding.confidence.desc())
    )
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = await session.scalars(stmt)
    return list(rows)


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str, session: AsyncSession = Depends(get_session)
) -> Finding:
    stmt = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.evidences))
    )
    finding = await session.scalar(stmt)
    if finding is None:
        raise HTTPException(404, "Achado nao encontrado")
    return finding
