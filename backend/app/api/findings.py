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
    diag: dict = {"com_produto": 0, "sem_produto": 0, "produtos": {}}

    cleared = 0
    for f in findings:
        d = f.data or {}
        # Achados de EXPOSIÇÃO/conteúdo/recon não recebem CVE de produto. Se tinham
        # CVE associado por engano (falsos CRÍTICOS), limpa e corrige a severidade.
        is_exposure = (
            d.get("path") is not None
            or f.service in ("content", "dns", "protection", "diag")
            or d.get("kind") in ("coverage", "api_surface", "protection",
                                  "protection_absent", "dns_info")
            or d.get("source") in ("content_discovery", "net_recon", "web_content",
                                    "api_exploit_surface"))
        if is_exposure:
            if f.cve_ids or d.get("potential_cves") or d.get("cve_rule"):
                f.cve_ids = []
                f.cvss = None
                hint = d.get("severity_hint")
                if hint in ("info", "low", "medium", "high", "critical"):
                    f.severity = Severity(hint)
                for k in ("potential_cves", "cve_rule", "cve_rule_reason", "cve_source"):
                    d.pop(k, None)
                f.data = d
                cleared += 1
                updated += 1
            continue
        prod, ver = extract_pv(d, f.title or "")
        if not prod:
            diag["sem_produto"] += 1
            continue
        diag["com_produto"] += 1
        from app.enrichment.local_cve import is_hosting, product_to_cpe
        mapped = product_to_cpe(prod)
        if is_hosting(prod):
            cpe_key = f"«{(prod or '')[:40]}» = hospedagem estática (sem software versionado → sem CVE)"
        else:
            cpe_key = mapped or f"(sem mapeamento) «{(prod or '')[:50]}» ver={ver or '-'}"
        diag["produtos"][cpe_key] = diag["produtos"].get(cpe_key, 0) + 1
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
        # Sem versao / sem match confirmado -> REGRA conservadora: associa o CVE
        # de MENOR severidade como linha de base (severidade real, nao INFO) e
        # lista os demais como POSSIBILIDADES, informando o motivo.
        pk = prod.lower()
        if pk not in pot_cache:
            pot_cache[pk] = await cves_for_product(session, prod)
        pot = pot_cache[pk]
        if pot and not (f.cve_ids or []):
            with_cvss = [c for c in pot if c.get("cvss") is not None]
            rule_cve = (min(with_cvss, key=lambda c: c["cvss"])
                        if with_cvss else pot[0])
            d = dict(f.data or {})
            f.cve_ids = [rule_cve["cve_id"]]
            cv = rule_cve.get("cvss")
            if cv is not None:
                f.cvss = cv
            # Severidade conservadora = a do CVE de MENOR risco (nunca INFO:
            # existe CVE conhecido do produto). Sem CVSS -> 'low'.
            f.severity = Severity(_sev_from_cvss(cv) or "low")
            d["cve_source"] = "regra: menor severidade (versão não detectada)"
            d["cve_rule"] = rule_cve["cve_id"]
            d["cve_rule_reason"] = (
                "A versão do serviço não foi identificada. Pela regra "
                "conservadora, associamos o CVE de MENOR severidade conhecido do "
                "produto como linha de base; os demais CVEs do produto ficam como "
                "POSSIBILIDADES e só se confirmam com a versão exata do serviço.")
            others = [c for c in pot if c["cve_id"] != rule_cve["cve_id"]]
            d["potential_cves"] = others
            f.data = d
            potential += 1
            updated += 1

    await session.commit()
    return {"total": len(findings), "updated": updated, "cleared": cleared,
            "confirmed": confirmed, "potential": potential, "diag": diag}


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
