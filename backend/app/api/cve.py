"""Base local de CVE: status + atualizacao (manual; agenda roda no worker)."""
from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.enrichment.cve_import import (
    base_status,
    get_import_status,
    get_schedule,
    import_status_dict,
    recent_cves,
)
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
    st["import"] = import_status_dict(await get_import_status(session))
    return st


@router.get("/cve/recent")
async def cve_recent(
    limit: int = 30,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return {"cves": await recent_cves(session, limit)}


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
    resume: bool = False,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Dispara a atualizacao da base de CVE em background (worker).

    Restrito ao admin (item de administracao).
    - full=false (padrao): re-busca remediacao dos CVEs ja vistos (leve).
    - full=true: baixa o bundle oficial e importa tudo (pesado).
    - resume=true (com full): RETOMA um download travado de onde parou, sem
      zerar o progresso (usado quando o worker morreu no meio).
    """
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin pode atualizar a base de CVE.")

    if full:
        from datetime import datetime, timezone
        st = await get_import_status(session)
        d = import_status_dict(st)
        # So bloqueia se houver um download REALMENTE vivo (nao travado).
        if st.state in ("connecting", "downloading") and not d.get("stale"):
            raise HTTPException(409, "Já existe um download em andamento.")
        # Retoma se pedido (e ha de onde retomar); senao, comeca do zero.
        resume = bool(resume and st.processed and st.total)
        st.state = "connecting"
        st.phase = "na fila (retomando)…" if resume else "na fila…"
        st.error = None
        st.cancel_requested = False
        if not resume:
            st.processed = 0
            st.imported = 0
            st.total = 0
        st.started_at = datetime.now(timezone.utc)
        st.updated_at = st.started_at
        st.finished_at = None
        await session.commit()

    pool = getattr(request.app.state, "redis_pool", None)
    if pool is None:
        pool = await create_pool(RedisSettings.from_dsn(request.app.state.redis_url))
    await pool.enqueue_job("update_cve_base", full, resume)
    return {"queued": True, "full": full, "resume": resume,
            "mensagem": (
                ("Retomando o download de onde parou…" if resume
                 else "Download da base completa iniciado (acompanhe o progresso).")
                if full else "Atualizacao dos CVEs vistos iniciada.")}


@router.post("/cve/import/cancel")
async def cve_import_cancel(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Para o download em andamento.

    Worker vivo: pede o cancelamento (ele para na proxima pagina).
    Worker morto (status "travado"/stale): forca o reset na hora, pois nao ha
    ninguem para ler o pedido e sair do estado "baixando"."""
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin pode cancelar.")
    st = await get_import_status(session)
    forced = False
    if st.state in ("connecting", "downloading"):
        st.cancel_requested = True
        if import_status_dict(st).get("stale"):
            from datetime import datetime, timezone
            st.state = "cancelled"
            st.phase = "cancelado (download travado — forçado)"
            st.finished_at = datetime.now(timezone.utc)
            st.updated_at = st.finished_at
            forced = True
        await session.commit()
    return {"cancel_requested": True, "forced": forced}
