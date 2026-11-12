"""Listagem de achados com evidencias, para o painel e os relatorios."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import can_access, get_current_user, require_engagement_access
from app.db import get_session
from app.models import Engagement, Evidence, Finding, User
from app.schemas import FindingOut

router = APIRouter(tags=["findings"])


class DeleteFindingsBody(BaseModel):
    ids: list[str]


@router.post("/engagements/{engagement_id}/findings/delete")
async def delete_findings(
    body: DeleteFindingsBody,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Exclui os achados selecionados (e suas evidencias) deste cliente."""
    if not body.ids:
        return {"deleted": 0}
    # So apaga achados que pertencem a este engagement (seguranca).
    rows = list(await session.scalars(
        select(Finding.id).where(
            Finding.engagement_id == eng.id, Finding.id.in_(body.ids))))
    if rows:
        await session.execute(delete(Evidence).where(Evidence.finding_id.in_(rows)))
        await session.execute(delete(Finding).where(Finding.id.in_(rows)))
        await session.commit()
    return {"deleted": len(rows)}


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
