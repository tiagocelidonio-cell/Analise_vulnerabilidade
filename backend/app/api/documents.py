"""Documentos do engagement: NDA, autorizacao, carta, relatorio anterior.

Guardados no banco (opcional, nao obrigatorios). Importantes para auditoria e
para anexar/registrar no relatorio. Apenas quem tem acesso ao engagement.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import can_access, get_current_user, require_engagement_access
from app.db import get_session
from app.models import Engagement, EngagementDocument, User

router = APIRouter(tags=["documents"])

_KINDS = {"nda", "authorization", "goocj", "prior_report", "other"}
_MAX = 15 * 1024 * 1024  # 15 MB por arquivo


def _meta(d: EngagementDocument) -> dict:
    return {
        "id": d.id, "kind": d.kind, "filename": d.filename,
        "content_type": d.content_type, "size": d.size,
        "uploaded_by": d.uploaded_by,
        "uploaded_at": d.uploaded_at.isoformat() if d.uploaded_at else None,
    }


@router.get("/engagements/{engagement_id}/documents")
async def list_documents(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    rows = await session.scalars(
        select(EngagementDocument)
        .where(EngagementDocument.engagement_id == eng.id)
        .order_by(EngagementDocument.uploaded_at.desc()))
    return [_meta(d) for d in rows]


@router.post("/engagements/{engagement_id}/documents", status_code=201)
async def upload_document(
    kind: str = Form("other"),
    file: UploadFile = File(...),
    eng: Engagement = Depends(require_engagement_access),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    data = await file.read()
    if len(data) == 0:
        raise HTTPException(400, "Arquivo vazio.")
    if len(data) > _MAX:
        raise HTTPException(413, "Arquivo maior que 15 MB.")
    doc = EngagementDocument(
        engagement_id=eng.id,
        kind=kind if kind in _KINDS else "other",
        filename=(file.filename or "arquivo")[:200],
        content_type=file.content_type or "application/octet-stream",
        size=len(data), data=data, uploaded_by=user.email,
    )
    session.add(doc)
    await session.commit()
    await session.refresh(doc)
    return _meta(doc)


async def _load(session: AsyncSession, user: User, doc_id: str) -> EngagementDocument:
    doc = await session.get(EngagementDocument, doc_id)
    if doc is None:
        raise HTTPException(404, "Documento nao encontrado")
    eng = await session.get(Engagement, doc.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(403, "Sem acesso")
    return doc


@router.get("/documents/{doc_id}")
async def download_document(
    doc_id: str,
    token: str | None = None,  # permite abrir em nova aba
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    doc = await _load(session, user, doc_id)
    return Response(
        content=doc.data, media_type=doc.content_type,
        headers={"Content-Disposition": f'inline; filename="{doc.filename}"'})


@router.delete("/documents/{doc_id}")
async def delete_document(
    doc_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    doc = await _load(session, user, doc_id)
    await session.delete(doc)
    await session.commit()
    return {"deleted": doc_id}
