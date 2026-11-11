"""Disparo e acompanhamento de scans. Aqui mora o gate de autorizacao."""
from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Engagement, ScanJob, ScanStatus
from app.schemas import ScanCreate, ScanOut
from app.scope import validate_targets

router = APIRouter(tags=["scans"])


@router.post("/engagements/{engagement_id}/scans", response_model=ScanOut, status_code=201)
async def create_scan(
    engagement_id: str,
    body: ScanCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ScanJob:
    eng = await session.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "Engagement nao encontrado")

    # GATE 1: autorizacao assinada.
    if not eng.authorized:
        raise HTTPException(
            403, "Engagement sem autorizacao. Marque authorized=true antes de escanear."
        )

    # GATE 2: todo alvo precisa estar no escopo autorizado.
    out_of_scope = validate_targets(body.targets, eng.scope)
    if out_of_scope:
        raise HTTPException(
            422, f"Alvos fora do escopo autorizado: {out_of_scope}"
        )

    scan = ScanJob(
        engagement_id=engagement_id,
        targets=body.targets,
        ports=body.ports,
        status=ScanStatus.queued,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    # Enfileira no worker (nao trava o painel).
    pool = getattr(request.app.state, "redis_pool", None)
    if pool is None:
        pool = await create_pool(RedisSettings.from_dsn(request.app.state.redis_url))
    await pool.enqueue_job("run_scan", scan.id)

    return scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str, session: AsyncSession = Depends(get_session)
) -> ScanJob:
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan nao encontrado")
    return scan


@router.get("/engagements/{engagement_id}/scans", response_model=list[ScanOut])
async def list_scans(
    engagement_id: str, session: AsyncSession = Depends(get_session)
) -> list[ScanJob]:
    rows = await session.scalars(
        select(ScanJob)
        .where(ScanJob.engagement_id == engagement_id)
        .order_by(ScanJob.created_at.desc())
    )
    return list(rows)
