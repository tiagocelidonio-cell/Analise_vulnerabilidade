"""Listagem de achados com evidencias, para o painel e os relatorios."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import can_access, get_current_user, require_engagement_access
from app.db import get_session
from app.models import Engagement, Evidence, Finding, User
from app.schemas import FINDING_STATUSES, FindingOut, FindingUpdate

router = APIRouter(tags=["findings"])


def _sev_from_cvss(cvss):
    if cvss is None:
        return None
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


@router.post("/engagements/{engagement_id}/reenrich-cves")
async def reenrich_cves(
    engagement_id: str,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Re-associa CVEs da BASE LOCAL aos achados JA EXISTENTES (sem re-escanear).

    Usa o produto/versao ja detectado em cada achado. Confirma (cve_ids) quando
    ha versao; senao anexa CVEs potenciais do produto. Agrupa por produto para
    fazer poucas consultas (rapido)."""
    from app.enrichment.local_cve import (
        cves_for_product, cves_for_service, extract_pv)
    from app.models import Severity

    findings = list(await session.scalars(
        select(Finding).where(Finding.engagement_id == engagement_id)))
    conf_cache: dict = {}
    pot_cache: dict = {}
    updated = confirmed = potential = 0

    for f in findings:
        prod, ver = extract_pv(f.data or {}, f.title or "")
        if not prod:
            continue
        cves = []
        if ver:
            key = (prod.lower(), ver)
            if key not in conf_cache:
                conf_cache[key] = await cves_for_service(session, prod, ver)
            cves = conf_cache[key]
        if cves:  # CONFIRMADO (produto + versao)
            f.cve_ids = [c["cve_id"] for c in cves]
            mx = max((c["cvss"] for c in cves if c["cvss"] is not None), default=None)
            if mx is not None:
                f.cvss = mx
                sv = _sev_from_cvss(mx)
                if sv:
                    f.severity = Severity(sv)
            d = dict(f.data or {})
            d["cve_source"] = "base local (versão)"
            d.pop("potential_cves", None)
            f.data = d
            confirmed += 1
            updated += 1
            continue
        # Sem versao / sem match confirmado -> CVEs POTENCIAIS do produto.
        pk = prod.lower()
        if pk not in pot_cache:
            pot_cache[pk] = await cves_for_product(session, prod)
        pot = pot_cache[pk]
        if pot and not (f.cve_ids or []):
            d = dict(f.data or {})
            d["potential_cves"] = pot
            f.data = d
            potential += 1
            updated += 1

    await session.commit()
    return {"total": len(findings), "updated": updated,
            "confirmed": confirmed, "potential": potential}


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: str,
    body: FindingUpdate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Finding:
    """Atualiza o ciclo de vida do achado (status/responsavel/notas)."""
    stmt = (
        select(Finding).where(Finding.id == finding_id)
        .options(selectinload(Finding.evidences))
    )
    f = await session.scalar(stmt)
    if f is None:
        raise HTTPException(404, "Achado nao encontrado")
    eng = await session.get(Engagement, f.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este achado")
    if body.status is not None and body.status in FINDING_STATUSES:
        f.status = body.status
    if body.assignee is not None:
        f.assignee = body.assignee.strip() or None
    if body.notes is not None:
        f.notes = body.notes or None
    await session.commit()
    await session.refresh(f)
    return f


class DeleteFindingsBody(BaseModel):
    ids: list[str]


@router.post("/engagements/{engagement_id}/findings/delete")
async def delete_findings(
    body: DeleteFindingsBody,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Exclui os achados selecionados (e suas evidencias) deste cliente."""
    if not body.ids:
        return {"deleted": 0}
    # So apaga achados que pertencem a este engagement (seguranca).
    rows = list(await session.scalars(
        select(Finding.id).where(
            Finding.engagement_id == eng.id, Finding.id.in_(body.ids))))
    if rows:
        await session.execute(delete(Evidence).where(Evidence.finding_id.in_(rows)))
        await session.execute(delete(Finding).where(Finding.id.in_(rows)))
        await session.commit()
    return {"deleted": len(rows)}


@router.get("/engagements/{engagement_id}/findings", response_model=list[FindingOut])
async def list_findings(
    severity: str | None = None,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    stmt = (
        select(Finding)
        .where(Finding.engagement_id == eng.id)
        .options(selectinload(Finding.evidences))
        .order_by(Finding.confidence.desc())
    )
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = await session.scalars(stmt)
    return list(rows)


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Finding:
    stmt = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.evidences))
    )
    finding = await session.scalar(stmt)
    if finding is None:
        raise HTTPException(404, "Achado nao encontrado")
    eng = await session.get(Engagement, finding.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso a este achado")
    return finding
