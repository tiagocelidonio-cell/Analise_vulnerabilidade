"""Base local de CVE: status + atualizacao (manual; agenda roda no worker)."""
from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.enrichment.cve_import import base_status
from app.models import User

router = APIRouter(tags=["cve"])


@router.get("/cve/status")
async def cve_status(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await base_status(session)


@router.post("/cve/update")
async def cve_update(
    request: Request,
    full: bool = False,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Dispara a atualizacao da base de CVE em background (worker).

    - full=false (padrao): re-busca remediacao dos CVEs ja vistos (leve).
    - full=true: baixa o bundle oficial e importa tudo (pesado, so admin).
    """
    if full and user.role != "admin":
        raise HTTPException(403, "Importacao completa e restrita ao admin.")

    pool = getattr(request.app.state, "redis_pool", None)
    if pool is None:
        pool = await create_pool(RedisSettings.from_dsn(request.app.state.redis_url))
    await pool.enqueue_job("update_cve_base", full)
    return {"queued": True, "full": full,
            "mensagem": ("Importacao completa iniciada (pode demorar)." if full
                         else "Atualizacao dos CVEs vistos iniciada.")}
