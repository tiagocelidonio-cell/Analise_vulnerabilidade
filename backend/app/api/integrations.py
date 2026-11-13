"""Chaves de API / integracoes — geridas pelo admin no painel.

As chaves ficam no banco (api_credentials) e SOBREPOEM o .env. O valor nunca e
devolvido ao front (so o status "configurada"). Cada processo chama
apply_db_keys() para sincronizar o objeto settings a partir do banco.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import settings
from app.db import get_session
from app.models import ApiCredential, User

router = APIRouter(tags=["integrations"])

# Catalogo das integracoes. `attr` = campo em settings; `fields` = chaves no banco.
INTEGRATIONS = [
    {
        "id": "nvd", "label": "NVD (base de CVE)", "required": False,
        "help": "Acelera o download da base de CVE (sem chave: 5 req/30s; com "
                "chave: 50 req/30s). Gratuita.",
        "link": "https://nvd.nist.gov/developers/request-an-api-key",
        "fields": [{"name": "nvd_api_key", "label": "API Key"}],
    },
    {
        "id": "anthropic", "label": "Claude API (análise por IA)", "required": False,
        "help": "Sem chave, a análise usa um modo heurístico (stub). Com a chave "
                "da Anthropic, a IA raciocina sobre os achados.",
        "link": "https://console.anthropic.com/settings/keys",
        "fields": [{"name": "anthropic_api_key", "label": "API Key"}],
    },
    {
        "id": "google_cse", "label": "Google Programmable Search (Dorks/OSINT)", "required": False,
        "help": "Liga a busca REAL dos Google Dorks e a coleta de e-mails do OSINT. "
                "Crie o mecanismo (CX) e a chave (API key). Cota grátis 100/dia.",
        "link": "https://programmablesearchengine.google.com",
        "fields": [{"name": "google_cse_key", "label": "API Key"},
                   {"name": "google_cse_cx", "label": "CX (ID do mecanismo)"}],
    },
    {
        "id": "hibp", "label": "Have I Been Pwned (vazamentos)", "required": False,
        "help": "Liga a ferramenta de Vazamentos (checa e-mails/domínios em "
                "breaches conhecidos). A API de conta do HIBP é paga.",
        "link": "https://haveibeenpwned.com/API/Key",
        "fields": [{"name": "hibp_api_key", "label": "API Key"}],
    },
]
_ALL_FIELDS = {f["name"] for it in INTEGRATIONS for f in it["fields"]}


async def apply_db_keys(session: AsyncSession) -> None:
    """Sincroniza o settings a partir do banco (linha existente SOBREPOE o env)."""
    rows = await session.scalars(select(ApiCredential))
    for r in rows:
        if r.key_name in _ALL_FIELDS:
            setattr(settings, r.key_name, r.value or "")


class IntegrationsBody(BaseModel):
    # {nome_do_campo: valor}. Valor vazio limpa. Campos ausentes nao mudam.
    updates: dict[str, str]


def _status() -> list[dict]:
    out = []
    for it in INTEGRATIONS:
        fields = [{
            "name": f["name"], "label": f["label"],
            "configured": bool(getattr(settings, f["name"], "")),
        } for f in it["fields"]]
        out.append({
            "id": it["id"], "label": it["label"], "required": it["required"],
            "help": it["help"], "link": it["link"],
            "fields": fields,
            "configured": all(f["configured"] for f in fields),
        })
    return out


@router.get("/integrations")
async def get_integrations(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin.")
    await apply_db_keys(session)
    return {"integrations": _status()}


@router.put("/integrations")
async def put_integrations(
    body: IntegrationsBody,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin pode alterar as chaves.")
    for name, value in body.updates.items():
        if name not in _ALL_FIELDS:
            continue
        row = await session.get(ApiCredential, name)
        if row is None:
            row = ApiCredential(key_name=name)
            session.add(row)
        row.value = value or ""
        row.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await apply_db_keys(session)   # reflete ja no settings deste processo (API)
    return {"integrations": _status()}
