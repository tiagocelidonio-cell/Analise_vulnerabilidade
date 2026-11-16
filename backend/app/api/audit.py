"""Trilha de auditoria (somente admin)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.db import get_session
from app.models import AuditLog, User

router = APIRouter(tags=["audit"])


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
