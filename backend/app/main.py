"""Aplicacao FastAPI — ponto de entrada da API."""
from __future__ import annotations

from contextlib import asynccontextmanager

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import engagements, findings, reports, scans
from app.config import settings
from app.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
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

app.include_router(engagements.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "ai_enabled": settings.ai_enabled}
