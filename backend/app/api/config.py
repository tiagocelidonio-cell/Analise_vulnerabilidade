"""Configuracao da plataforma: nome, logo, identidade visual e fuso horario.

GET e publico (o painel e a tela de login aplicam a marca antes do login).
PUT e restrito ao admin.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.models import PlatformConfig, User

router = APIRouter(tags=["config"])


class ConfigBody(BaseModel):
    platform_name: str | None = None
    logo: str | None = None          # data URI (ou "" para remover)
    colors: dict | None = None
    font: str | None = None
    heading_font: str | None = None
    timezone: str | None = None


def _out(c: PlatformConfig) -> dict:
    return {
        "platform_name": c.platform_name,
        "logo": c.logo,
        "colors": c.colors or {},
        "font": c.font,
        "heading_font": c.heading_font,
        "timezone": c.timezone,
    }


async def _get_or_create(session: AsyncSession) -> PlatformConfig:
    c = await session.get(PlatformConfig, "main")
    if c is None:
        c = PlatformConfig(id="main")
        session.add(c)
        await session.commit()
        await session.refresh(c)
    return c


@router.get("/config")
async def get_config(session: AsyncSession = Depends(get_session)) -> dict:
    return _out(await _get_or_create(session))


@router.put("/config")
async def put_config(
    body: ConfigBody,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if user.role != "admin":
        raise HTTPException(403, "Apenas admin pode alterar a configuracao.")
    c = await _get_or_create(session)
    if body.platform_name is not None:
        c.platform_name = body.platform_name.strip() or "VulnScope"
    if body.logo is not None:
        c.logo = body.logo or None
    if body.colors is not None:
        c.colors = body.colors
    if body.font is not None:
        c.font = body.font or None
    if body.heading_font is not None:
        c.heading_font = body.heading_font or None
    if body.timezone is not None:
        c.timezone = body.timezone.strip() or "UTC"
    c.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(c)
    return _out(c)
