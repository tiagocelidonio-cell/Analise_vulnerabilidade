"""Disparo e acompanhamento de scans. Gate de autorizacao + controle de acesso."""
from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select, update
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
        profile=body.profile if body.profile in ("basic", "full") else "full",
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
        # Cancela de imediato (feedback instantaneo e cobre scan orfao).
        # O worker, se ainda estiver vivo, para no proximo checkpoint; como ele
        # so atualiza progress/phase, nao sobrescreve o status cancelado.
        scan.cancel_requested = True
        scan.status = ScanStatus.cancelled
        scan.phase = "cancelado"
        await session.commit()
        await session.refresh(scan)
    return scan


@router.post("/scans/{scan_id}/pause", response_model=ScanOut)
async def pause_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanJob:
    """Pausa o scan: ele para no proximo checkpoint, PRESERVANDO os achados ja
    coletados. Diferente de 'cancelar', pode ser retomado depois."""
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan nao encontrado")
    eng = await session.get(Engagement, scan.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este scan")
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        scan.pause_requested = True
        scan.status = ScanStatus.paused
        scan.phase = "pausado"
        await session.commit()
        await session.refresh(scan)
    return scan


@router.post("/scans/{scan_id}/resume", response_model=ScanOut)
async def resume_scan(
    scan_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanJob:
    """Retoma um scan pausado. Re-enfileira a execucao; a deduplicacao por
    assinatura evita achados repetidos, entao as fases restantes continuam."""
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan nao encontrado")
    eng = await session.get(Engagement, scan.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este scan")
    if scan.status == ScanStatus.paused:
        scan.pause_requested = False
        scan.cancel_requested = False
        scan.status = ScanStatus.queued
        scan.phase = "na fila (retomando)"
        await session.commit()
        await session.refresh(scan)

        pool = getattr(request.app.state, "redis_pool", None)
        if pool is None:
            pool = await create_pool(RedisSettings.from_dsn(request.app.state.redis_url))
        await pool.enqueue_job("run_scan", scan.id)
    return scan


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Exclui um scan do historico. Os ACHADOS sao preservados (apenas perdem
    o vinculo com este scan), pois sao deduplicados entre varreduras."""
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan nao encontrado")
    eng = await session.get(Engagement, scan.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este scan")
    if scan.status in (ScanStatus.queued, ScanStatus.running):
        # Para primeiro (evita worker escrevendo num scan excluido).
        scan.cancel_requested = True
        scan.status = ScanStatus.cancelled
        await session.commit()
    # Desvincula os achados (nao os apaga) e remove o scan via core (sem cascade).
    from app.models import Finding
    await session.execute(
        update(Finding).where(Finding.scan_id == scan_id).values(scan_id=None))
    await session.execute(delete(ScanJob).where(ScanJob.id == scan_id))
    await session.commit()
    return {"deleted": scan_id}


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
