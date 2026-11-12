"""Inventario de Ativos (estilo Pentest-Tools 'Assets').

Um ativo e um host/dominio/IP do escopo ou descoberto. Agrega, por ativo:
nivel de risco (maior severidade dos achados), nº de achados e tipo.
"""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_engagement_access
from app.db import get_session
from app.models import Engagement, Finding, ScanJob

router = APIRouter(tags=["assets"])

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _asset_type(t: str) -> str:
    try:
        net = ipaddress.ip_network(t, strict=False)
        return "range" if net.num_addresses > 1 else "ip"
    except ValueError:
        return "hostname"


@router.get("/engagements/{engagement_id}/assets")
async def list_assets(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    findings = list(await session.scalars(
        select(Finding).where(Finding.engagement_id == eng.id)))
    scans = list(await session.scalars(
        select(ScanJob).where(ScanJob.engagement_id == eng.id)))

    assets: dict[str, dict] = {}

    def ensure(name: str):
        name = (name or "").strip()
        if not name:
            return None
        a = assets.setdefault(name, {
            "target": name, "type": _asset_type(name),
            "risk": "info", "findings": 0, "scans": 0, "first_seen": None})
        return a

    def _seen(a: dict, dt) -> None:
        if dt is None:
            return
        iso = dt.isoformat()
        if a["first_seen"] is None or iso < a["first_seen"]:
            a["first_seen"] = iso

    # Escopo + alvos de scans entram como ativos mesmo sem achados.
    for s in eng.scope or []:
        ensure(s)
    for sc in scans:
        for t in sc.targets or []:
            a = ensure(t)
            if a:
                a["scans"] += 1
                _seen(a, sc.created_at)

    # Achados elevam o risco e a contagem do ativo.
    for f in findings:
        a = ensure(f.target)
        if a is None:
            continue
        a["findings"] += 1
        _seen(a, f.created_at)
        sev = f.severity.value
        if _SEV_RANK.get(sev, 1) > _SEV_RANK.get(a["risk"], 1):
            a["risk"] = sev

    items = sorted(assets.values(),
                   key=lambda x: (_SEV_RANK.get(x["risk"], 1), x["findings"]),
                   reverse=True)
    return {"total": len(items), "assets": items}
