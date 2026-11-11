"""Aplicacao FastAPI — ponto de entrada da API."""
from __future__ import annotations

from contextlib import asynccontextmanager

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth as auth_api
from app.api import engagements, exploit, findings, reports, risk, scans
from app.auth import ensure_seed_admin, get_current_user
from app.config import settings
from app.db import SessionLocal, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with SessionLocal() as session:
        await ensure_seed_admin(session)
    app.state.redis_url = settings.redis_url
    app.state.redis_pool = await create_pool(
        RedisSettings.from_dsn(settings.redis_url)
    )
    yield
    await app.state.redis_pool.close()


app = FastAPI(title="VulnScope API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restringir ao dominio do painel em producao
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rotas publicas (sem auth): login e health.
app.include_router(auth_api.router)

# Rotas de negocio: exigem usuario autenticado.
_auth = [Depends(get_current_user)]
app.include_router(engagements.router, dependencies=_auth)
app.include_router(scans.router, dependencies=_auth)
app.include_router(findings.router, dependencies=_auth)
app.include_router(reports.router, dependencies=_auth)
app.include_router(risk.router, dependencies=_auth)
app.include_router(exploit.router, dependencies=_auth)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "ai_enabled": settings.ai_enabled}
