"""CRUD de Engagements — o centro de tudo. Multi-tenant por dono."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_engagement_access
from app.db import get_session
from app.models import (
    Engagement,
    EngagementDocument,
    Evidence,
    Finding,
    ScanJob,
    User,
)
from app.schemas import EngagementCreate, EngagementOut, EngagementUpdate

router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.post("", response_model=EngagementOut, status_code=201)
async def create_engagement(
    body: EngagementCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Engagement:
    from app.schemas import ENGAGEMENT_TYPES
    data = body.model_dump()
    if data.get("engagement_type") not in ENGAGEMENT_TYPES:
        data["engagement_type"] = "vuln_analysis"
    eng = Engagement(**data, owner_id=user.id)
    session.add(eng)
    await session.commit()
    await session.refresh(eng)
    return eng


@router.get("", response_model=list[EngagementOut])
async def list_engagements(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[Engagement]:
    stmt = select(Engagement).order_by(Engagement.created_at.desc())
    # Admin ve todos; consultor ve apenas os seus.
    if user.role != "admin":
        stmt = stmt.where(Engagement.owner_id == user.id)
    engs = list(await session.scalars(stmt))

    # Resolve o nome do consultor dono (para o admin agrupar na barra lateral).
    owner_ids = {e.owner_id for e in engs if e.owner_id}
    names: dict[str, str] = {}
    if owner_ids:
        urows = await session.scalars(select(User).where(User.id.in_(owner_ids)))
        names = {u.id: (u.name or u.email) for u in urows}
    for e in engs:
        e.owner_name = names.get(e.owner_id) if e.owner_id else None
    return engs


@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(
    eng: Engagement = Depends(require_engagement_access),
) -> Engagement:
    return eng


@router.patch("/{engagement_id}", response_model=EngagementOut)
async def update_engagement(
    body: EngagementUpdate,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> Engagement:
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(eng, field, value)
    await session.commit()
    await session.refresh(eng)
    return eng


@router.delete("/{engagement_id}", status_code=204)
async def delete_engagement(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
):
    """Exclui o cliente e TUDO que depende dele, na ordem das chaves estrangeiras
    (evidências → achados → scans → documentos → engagement). Sem isso o Postgres
    recusa a exclusão (FK violada em engagement_documents, findings, etc.)."""
    # 1) Evidências dos achados deste engagement.
    fids = list(await session.scalars(
        select(Finding.id).where(Finding.engagement_id == eng.id)))
    if fids:
        await session.execute(delete(Evidence).where(Evidence.finding_id.in_(fids)))
    # 2) Achados, scans e documentos.
    await session.execute(delete(Finding).where(Finding.engagement_id == eng.id))
    await session.execute(delete(ScanJob).where(ScanJob.engagement_id == eng.id))
    await session.execute(
        delete(EngagementDocument).where(EngagementDocument.engagement_id == eng.id))
    # 3) O próprio engagement.
    await session.execute(delete(Engagement).where(Engagement.id == eng.id))
    await session.commit()
