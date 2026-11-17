"""Trilha de auditoria (somente admin)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.db import get_session
from app.models import AuditLog, PlatformConfig, User

router = APIRouter(tags=["audit"])


async def _cfg(session: AsyncSession) -> PlatformConfig:
    cfg = await session.get(PlatformConfig, "main")
    if cfg is None:
        cfg = PlatformConfig(id="main")
        session.add(cfg)
        await session.commit()
        await session.refresh(cfg)
    return cfg


@router.get("/audit/config")
async def audit_config(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict:
    cfg = await _cfg(session)
    count = await session.scalar(select(func.count()).select_from(AuditLog))
    return {"enabled": cfg.audit_enabled, "count": int(count or 0)}


class AuditCfgBody(BaseModel):
    enabled: bool = True


@router.put("/audit/config")
async def set_audit_config(
    body: AuditCfgBody,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict:
    cfg = await _cfg(session)
    cfg.audit_enabled = bool(body.enabled)
    cfg.updated_at = datetime.now(timezone.utc)
    await session.commit()
    return {"enabled": cfg.audit_enabled}


@router.delete("/audit")
async def purge_audit(
    older_than_days: int | None = None,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Expurga a trilha de auditoria. Sem parametro: apaga TUDO. Com
    older_than_days=N: apaga so' o que for mais antigo que N dias."""
    if older_than_days and older_than_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        res = await session.execute(
            delete(AuditLog).where(AuditLog.created_at < cutoff))
    else:
        res = await session.execute(delete(AuditLog))
    await session.commit()
    return {"deleted": res.rowcount or 0}


@router.get("/audit")
async def list_audit(
    limit: int = 200,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    rows = list(await session.scalars(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(limit, 1000))))
    # resolve e-mail dos usuarios referenciados
    ids = {r.user_id for r in rows if r.user_id}
    emails: dict[str, str] = {}
    if ids:
        urows = await session.scalars(select(User).where(User.id.in_(ids)))
        emails = {u.id: u.email for u in urows}
    return [{
        "id": r.id, "user": emails.get(r.user_id, r.user_id or "—"),
        "method": r.method, "path": r.path, "status": r.status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]
