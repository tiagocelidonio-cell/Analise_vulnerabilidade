"""Endpoint de risco: matriz 5x5 + rankings para o dashboard executivo."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Engagement, Finding
from app.risk import build_matrix

router = APIRouter(tags=["risk"])


@router.get("/engagements/{engagement_id}/risk")
async def engagement_risk(
    engagement_id: str, session: AsyncSession = Depends(get_session)
) -> dict:
    eng = await session.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "Engagement nao encontrado")

    rows = await session.scalars(
        select(Finding).where(Finding.engagement_id == engagement_id)
    )
    findings = [
        {
            "id": f.id, "title": f.title, "target": f.target,
            "service": f.service, "severity": f.severity.value,
            "cvss": f.cvss, "epss": f.epss, "in_kev": f.in_kev,
            "cve_ids": f.cve_ids,
        }
        for f in rows
    ]
    data = build_matrix(findings)
    data["engagement"] = {"id": eng.id, "name": eng.name, "client_name": eng.client_name}
    return data
