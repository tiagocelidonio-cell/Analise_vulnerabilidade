"""Disparo e acompanhamento de scans. Gate de autorizacao + controle de acesso."""
from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import can_access, get_current_user, require_engagement_access
from app.db import get_session
from app.models import Engagement, ScanJob, ScanStatus, User
from app.schemas import ScanCreate, ScanOut
from app.scope import validate_targets
from app.targets import host_count

router = APIRouter(tags=["scans"])


@router.post("/engagements/{engagement_id}/scans", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    request: Request,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> ScanJob:
    # GATE 1: autorizacao assinada.
    if not eng.authorized:
        raise HTTPException(
            403, "Engagement sem autorizacao. Marque authorized=true antes de escanear."
        )

    # GATE 2: todo alvo precisa estar no escopo autorizado.
    out_of_scope = validate_targets(body.targets, eng.scope)
    if out_of_scope:
        raise HTTPException(422, f"Alvos fora do escopo autorizado: {out_of_scope}")

    # GATE 3: ranges nao podem ser gigantes (teto de seguranca).
    try:
        host_count(body.targets)
    except ValueError as exc:
        raise HTTPException(422, str(exc))

    scan = ScanJob(
        engagement_id=eng.id,
        targets=body.targets,
        ports=body.ports,
        collectors=body.collectors,
        status=ScanStatus.queued,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    pool = getattr(request.app.state, "redis_pool", None)
    if pool is None:
        pool = await create_pool(RedisSettings.from_dsn(request.app.state.redis_url))
    await pool.enqueue_job("run_scan", scan.id)

    return scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanJob:
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan nao encontrado")
    eng = await session.get(Engagement, scan.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este scan")
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanJob:
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan nao encontrado")
    eng = await session.get(Engagement, scan.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este scan")
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        scan.cancel_requested = True
        # Se ainda nem comecou, cancela de imediato.
        if scan.status == ScanStatus.queued:
            scan.status = ScanStatus.cancelled
            scan.phase = "cancelado"
        await session.commit()
        await session.refresh(scan)
    return scan


@router.get("/engagements/{engagement_id}/scans", response_model=list[ScanOut])
async def list_scans(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> list[ScanJob]:
    rows = await session.scalars(
        select(ScanJob)
        .where(ScanJob.engagement_id == eng.id)
        .order_by(ScanJob.created_at.desc())
    )
    return list(rows)
