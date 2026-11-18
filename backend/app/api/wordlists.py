"""Biblioteca de CREDENCIAIS para o ataque de credenciais (gated).

Listas nomeadas de senhas / usuários / pares (user:pass). Inclui listas públicas
embutidas (curadas) e permite criar/colar/importar as suas. Usadas pelo coletor
cred_attack, escolhidas na hora do scan.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.models import CredentialList, User

router = APIRouter(tags=["wordlists"])

_KINDS = {"passwords", "users", "pairs"}
_MAX_LINES = 200_000
_MAX_BYTES = 8 * 1024 * 1024


def _count(content: str) -> int:
    return sum(1 for ln in (content or "").splitlines() if ln.strip())


def _meta(w: CredentialList) -> dict:
    return {"id": w.id, "name": w.name, "kind": w.kind, "count": w.count,
            "builtin": w.builtin, "created_by": w.created_by}


class WordlistBody(BaseModel):
    name: str
    kind: str = "passwords"
    content: str = ""


@router.get("/wordlists")
async def list_wordlists(
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    rows = await session.scalars(select(CredentialList).order_by(
        CredentialList.builtin.desc(), CredentialList.name))
    return [_meta(w) for w in rows]


@router.get("/wordlists/{wid}")
async def get_wordlist(
    wid: str, _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    w = await session.get(CredentialList, wid)
    if w is None:
        raise HTTPException(404, "Lista não encontrada")
    return {**_meta(w), "content": w.content}


@router.post("/wordlists", status_code=201)
async def create_wordlist(
    body: WordlistBody, user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    kind = body.kind if body.kind in _KINDS else "passwords"
    content = (body.content or "")
    if len(content) > _MAX_BYTES:
        raise HTTPException(413, "Lista muito grande (máx. ~8 MB).")
    if _count(content) > _MAX_LINES:
        raise HTTPException(413, f"Lista excede {_MAX_LINES} linhas.")
    w = CredentialList(name=(body.name or "Lista").strip()[:120], kind=kind,
                       content=content, count=_count(content),
                       created_by=user.email, builtin=False)
    session.add(w)
    await session.commit()
    await session.refresh(w)
    return _meta(w)


@router.put("/wordlists/{wid}")
async def update_wordlist(
    wid: str, body: WordlistBody, _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    w = await session.get(CredentialList, wid)
    if w is None:
        raise HTTPException(404, "Lista não encontrada")
    if w.builtin:
        raise HTTPException(400, "Listas embutidas não podem ser editadas (duplique-a).")
    if body.name:
        w.name = body.name.strip()[:120]
    if body.kind in _KINDS:
        w.kind = body.kind
    if body.content is not None:
        if len(body.content) > _MAX_BYTES or _count(body.content) > _MAX_LINES:
            raise HTTPException(413, "Lista muito grande.")
        w.content = body.content
        w.count = _count(body.content)
    await session.commit()
    await session.refresh(w)
    return _meta(w)


@router.delete("/wordlists/{wid}")
async def delete_wordlist(
    wid: str, _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    w = await session.get(CredentialList, wid)
    if w is None:
        raise HTTPException(404, "Lista não encontrada")
    if w.builtin:
        raise HTTPException(400, "Listas embutidas não podem ser excluídas.")
    await session.delete(w)
    await session.commit()
    return {"deleted": wid}
