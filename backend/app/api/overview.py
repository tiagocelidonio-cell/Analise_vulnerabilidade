"""Visao global (dashboard Lozinsky): agrega todos os clientes acessiveis
+ benchmarking de vulnerabilidades mais comuns.

Admin ve todos os clientes; consultor ve apenas os seus.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.benchmark import build_benchmark, categorize
from app.db import get_session
from app.models import Engagement, Finding, User
from app.risk import build_matrix, score_finding

router = APIRouter(tags=["overview"])

_SEV = ["critical", "high", "medium", "low", "info"]


async def compute_overview(session: AsyncSession, user: User) -> dict:
    stmt = select(Engagement)
    if user.role != "admin":
        stmt = stmt.where(Engagement.owner_id == user.id)
    engagements = list(await session.scalars(stmt))
    eng_by_id = {e.id: e for e in engagements}

    empty = {"total_clients": 0, "total_findings": 0, "severity_dist": {},
             "level_dist": {}, "top_clients": [], "benchmark": [], "insights": [],
             "matrix": [[0] * 5 for _ in range(5)], "avg_score": 0.0, "kev_count": 0}
    if not engagements:
        return empty

    rows = await session.scalars(
        select(Finding).where(Finding.engagement_id.in_(list(eng_by_id.keys()))))
    findings = list(rows)

    severity_dist = {s: 0 for s in _SEV}
    level_dist: dict[str, int] = {}
    per_client: dict[str, dict] = {}
    bench_items = []
    fd_list = []

    for f in findings:
        eng = eng_by_id.get(f.engagement_id)
        if eng is None:
            continue
        sev = f.severity.value
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        fd = {"severity": sev, "cvss": f.cvss, "epss": f.epss, "in_kev": f.in_kev,
              "service": f.service}
        fd_list.append(fd)
        s = score_finding(fd)
        level_dist[s["level"]] = level_dist.get(s["level"], 0) + 1

        c = per_client.setdefault(eng.id, {
            "client": eng.client_name, "name": eng.name, "total": 0,
            "crit_high": 0, "score_sum": 0})
        c["total"] += 1
        if sev in ("critical", "high"):
            c["crit_high"] += 1
        c["score_sum"] += s["score"]

        bench_items.append({
            "category": categorize(f.title, f.service, f.cve_ids),
            "client": eng.client_name, "severity": sev})

    top_clients = sorted(
        [{"client": c["client"], "name": c["name"], "total": c["total"],
          "crit_high": c["crit_high"],
          "avg_score": round(c["score_sum"] / c["total"], 1) if c["total"] else 0}
         for c in per_client.values()],
        key=lambda x: (x["crit_high"], x["avg_score"]), reverse=True)[:10]

    benchmark = build_benchmark(bench_items)
    agg = build_matrix(fd_list)

    insights = []
    if benchmark:
        top = benchmark[0]
        insights.append(
            f"Vulnerabilidade mais comum: '{top['category']}' — presente em "
            f"{top['clients']} cliente(s) ({top['prevalence']}% da base).")
    crit = severity_dist.get("critical", 0) + severity_dist.get("high", 0)
    if crit:
        insights.append(f"{crit} achado(s) de severidade alta/critica na base.")
    kev = sum(1 for f in findings if f.in_kev)
    if kev:
        insights.append(f"{kev} achado(s) com exploracao ativa (KEV) — prioridade maxima.")

    return {
        "total_clients": len(engagements),
        "total_findings": len(findings),
        "severity_dist": severity_dist,
        "level_dist": level_dist,
        "top_clients": top_clients,
        "benchmark": benchmark,
        "insights": insights,
        "matrix": agg["matrix"],
        "avg_score": agg["avg_score"],
        "kev_count": agg["kev_count"],
    }


@router.get("/overview")
async def overview(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await compute_overview(session, user)


@router.get("/overview/report.html", response_class=HTMLResponse)
async def overview_report_html(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    from app.reporting.overview_report import render_overview_html
    data = await compute_overview(session, user)
    return HTMLResponse(render_overview_html(data))


@router.get("/overview/report.pdf")
async def overview_report_pdf(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    from app.reporting.overview_report import render_overview_html
    from app.reporting.report import html_to_pdf
    data = await compute_overview(session, user)
    try:
        pdf = html_to_pdf(render_overview_html(data))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"Falha ao gerar PDF: {exc}")
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="benchmarking.pdf"'})
