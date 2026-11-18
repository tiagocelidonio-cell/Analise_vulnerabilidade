"""Ferramenta de rede (passiva): DNS, hospedagem, CDN/WAF, segurança de e-mail.

Informação pública (DNS + cabeçalhos HTTP), estilo MXToolbox. Disponível a
qualquer usuário autenticado; não faz varredura nem exploração.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.netinfo import network_lookup

router = APIRouter(tags=["netlookup"])


@router.get("/netlookup")
async def netlookup(target: str) -> dict:
    target = (target or "").strip()
    if not target:
        raise HTTPException(400, "Informe um domínio (ex.: exemplo.com.br).")
    res = await network_lookup(target)
    if res.get("error"):
        raise HTTPException(400, res["error"])
    return res
