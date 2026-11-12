"""Endpoints de relatorio: HTML (preview rapido) e PDF (entregavel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_engagement_access
from app.db import get_session
from app.models import Engagement
from app.reporting.report import ReportOptions, html_to_pdf, render_html

router = APIRouter(tags=["reports"])


def _opts(min_sev: str = "info", methodology: bool = True, matrix: bool = True,
          targets: bool = True, evidence: bool = True) -> ReportOptions:
    return ReportOptions.from_query(min_sev=min_sev, methodology=methodology,
                                    matrix=matrix, targets=targets, evidence=evidence)


@router.get("/engagements/{engagement_id}/report.html", response_class=HTMLResponse)
async def report_html(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
    opt: ReportOptions = Depends(_opts),
) -> HTMLResponse:
    html = await render_html(session, eng.id, opt)
    if html is None:
        raise HTTPException(404, "Engagement nao encontrado")
    return HTMLResponse(html)


@router.get("/engagements/{engagement_id}/report.pdf")
async def report_pdf(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
    opt: ReportOptions = Depends(_opts),
) -> Response:
    html = await render_html(session, eng.id, opt)
    if html is None:
        raise HTTPException(404, "Engagement nao encontrado")
    try:
        pdf = html_to_pdf(html)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            500, f"Falha ao gerar PDF (libs do WeasyPrint instaladas?): {exc}"
        )
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="report-{eng.id}.pdf"'
        },
    )
