"""Threat Intel — "Relevantes para voce".

Cruza os CVEs recentes da base local com as tecnologias detectadas nos ativos:
- por engagement: /engagements/{id}/relevant-cves
- carteira (todos os clientes que o usuario ve): /intel/relevant
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_engagement_access
from app.db import get_session
from app.enrichment.relevance import detected_tech_index, match_recent
from app.models import Engagement, Finding, User

router = APIRouter(tags=["intel"])


@router.get("/engagements/{engagement_id}/relevant-cves")
async def engagement_relevant(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    findings = list(await session.scalars(
        select(Finding).where(Finding.engagement_id == eng.id)))
    index = detected_tech_index(findings)
    matches = await match_recent(session, index, eng_names={eng.id: eng.client_name})
    return {
        "technologies": sorted(index.keys()),
        "matches": matches,
        "counts": {"technologies": len(index), "matches": len(matches)},
    }


@router.get("/intel/relevant")
async def portfolio_relevant(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """CVEs recentes que casam com a carteira do usuario (todos os clientes
    que ele ve). O grande diferencial: alerta por cliente."""
    q = select(Engagement)
    if user.role != "admin":
        q = q.where(Engagement.owner_id == user.id)
    engs = list(await session.scalars(q))
    if not engs:
        return {"matches": [], "counts": {"technologies": 0, "matches": 0,
                                          "clients": 0}}
    eng_names = {e.id: e.client_name for e in engs}
    ids = list(eng_names.keys())
    findings = list(await session.scalars(
        select(Finding).where(Finding.engagement_id.in_(ids))))
    index = detected_tech_index(findings)
    matches = await match_recent(session, index, eng_names=eng_names)
    clients = {c for m in matches for c in m["clients"]}
    return {
        "matches": matches,
        "counts": {"technologies": len(index), "matches": len(matches),
                   "clients": len(clients)},
    }
