"""Endpoints de relatorio: HTML (preview rapido) e PDF (entregavel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.reporting.report import html_to_pdf, render_html

router = APIRouter(tags=["reports"])


@router.get("/engagements/{engagement_id}/report.html", response_class=HTMLResponse)
async def report_html(
    engagement_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    html = await render_html(session, engagement_id)
    if html is None:
        raise HTTPException(404, "Engagement nao encontrado")
    return HTMLResponse(html)


@router.get("/engagements/{engagement_id}/report.pdf")
async def report_pdf(
    engagement_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    html = await render_html(session, engagement_id)
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
            "Content-Disposition": f'attachment; filename="report-{engagement_id}.pdf"'
        },
    )
