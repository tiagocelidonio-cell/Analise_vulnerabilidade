"""CRUD de Engagements — o centro de tudo."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Engagement
from app.schemas import EngagementCreate, EngagementOut

router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.post("", response_model=EngagementOut, status_code=201)
async def create_engagement(
    body: EngagementCreate, session: AsyncSession = Depends(get_session)
) -> Engagement:
    eng = Engagement(**body.model_dump())
    session.add(eng)
    await session.commit()
    await session.refresh(eng)
    return eng


@router.get("", response_model=list[EngagementOut])
async def list_engagements(
    session: AsyncSession = Depends(get_session),
) -> list[Engagement]:
    rows = await session.scalars(select(Engagement).order_by(Engagement.created_at.desc()))
    return list(rows)


@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(
    engagement_id: str, session: AsyncSession = Depends(get_session)
) -> Engagement:
    eng = await session.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "Engagement nao encontrado")
    return eng
