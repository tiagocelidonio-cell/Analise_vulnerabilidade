"""Endpoint de risco: matriz 5x5 + rankings para o dashboard executivo."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_engagement_access
from app.db import get_session
from app.models import Engagement, Finding
from app.risk import build_matrix

router = APIRouter(tags=["risk"])


@router.get("/engagements/{engagement_id}/risk")
async def engagement_risk(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    rows = await session.scalars(
        select(Finding).where(Finding.engagement_id == eng.id)
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
