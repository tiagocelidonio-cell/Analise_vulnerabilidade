"""Base local de CVE: status + atualizacao (manual; agenda roda no worker)."""
from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.enrichment.cve_import import base_status, get_schedule
from app.models import User

router = APIRouter(tags=["cve"])


def _sched_dict(cfg) -> dict:
    return {
        "enabled": cfg.enabled,
        "interval_hours": cfg.interval_hours,
        "full": cfg.full,
        "last_run": cfg.last_run.isoformat() if cfg.last_run else None,
        "last_result": cfg.last_result,
    }


class ScheduleBody(BaseModel):
    enabled: bool = False
    interval_hours: int = 24
    full: bool = False


@router.get("/cve/status")
async def cve_status(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    st = await base_status(session)
    cfg = await get_schedule(session)
    st["schedule"] = _sched_dict(cfg)
    return st


@router.get("/cve/schedule")
async def cve_schedule_get(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return _sched_dict(await get_schedule(session))


@router.put("/cve/schedule")
async def cve_schedule_set(
    body: ScheduleBody,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin pode configurar a agenda.")
    cfg = await get_schedule(session)
    cfg.enabled = body.enabled
    cfg.interval_hours = max(1, int(body.interval_hours))
    cfg.full = body.full
    from datetime import datetime, timezone
    cfg.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(cfg)
    return _sched_dict(cfg)


@router.post("/cve/update")
async def cve_update(
    request: Request,
    full: bool = False,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Dispara a atualizacao da base de CVE em background (worker).

    Restrito ao admin (item de administracao).
    - full=false (padrao): re-busca remediacao dos CVEs ja vistos (leve).
    - full=true: baixa o bundle oficial e importa tudo (pesado).
    """
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin pode atualizar a base de CVE.")

    pool = getattr(request.app.state, "redis_pool", None)
    if pool is None:
        pool = await create_pool(RedisSettings.from_dsn(request.app.state.redis_url))
    await pool.enqueue_job("update_cve_base", full)
    return {"queued": True, "full": full,
            "mensagem": ("Importacao completa iniciada (pode demorar)." if full
                         else "Atualizacao dos CVEs vistos iniciada.")}
