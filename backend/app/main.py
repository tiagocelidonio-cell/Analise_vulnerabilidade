"""Aplicacao FastAPI — ponto de entrada da API."""
from __future__ import annotations

import logging
import traceback
from contextlib import asynccontextmanager

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = logging.getLogger("vulnscope")

from app.api import auth as auth_api
from app.api import (
    assets,
    audit,
    config as config_api,
    cve,
    documents,
    engagements,
    exploit,
    findings,
    intel,
    integrations,
    overview,
    postexploit,
    reports,
    risk,
    scans,
    surface,
    topology,
)
from app.auth import ensure_seed_admin, get_current_user
from app.config import settings
from app.db import SessionLocal, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with SessionLocal() as session:
        await ensure_seed_admin(session)
        # Chaves de API salvas no painel sobrepoem o .env.
        from app.api.integrations import apply_db_keys
        await apply_db_keys(session)
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


@app.middleware("http")
async def _audit(request: Request, call_next):
    """Trilha de auditoria: registra toda mutacao (quem, o que, resultado)."""
    response = await call_next(request)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            from app.auth import _extract_token, decode_token
            from app.models import AuditLog
            token = _extract_token(request)
            sub = None
            if token:
                payload = decode_token(token)
                sub = payload.get("sub") if payload else None
            # nao registra o proprio login (ruido) nem leituras
            if request.url.path != "/auth/login":
                from app.models import PlatformConfig
                async with SessionLocal() as session:
                    cfg = await session.get(PlatformConfig, "main")
                    if cfg is None or cfg.audit_enabled:  # desligavel pelo admin
                        session.add(AuditLog(
                            user_id=sub, method=request.method,
                            path=request.url.path, status=response.status_code))
                        await session.commit()
        except Exception:  # noqa: BLE001  auditoria nunca quebra a requisicao
            pass
    return response

# Rotas publicas (sem auth): login, health e config (para aplicar a marca
# antes do login; o PUT de config valida admin internamente).
app.include_router(auth_api.router)
app.include_router(config_api.router)

# Rotas de negocio: exigem usuario autenticado.
_auth = [Depends(get_current_user)]
app.include_router(engagements.router, dependencies=_auth)
app.include_router(scans.router, dependencies=_auth)
app.include_router(findings.router, dependencies=_auth)
app.include_router(reports.router, dependencies=_auth)
app.include_router(risk.router, dependencies=_auth)
app.include_router(exploit.router, dependencies=_auth)
app.include_router(overview.router, dependencies=_auth)
app.include_router(postexploit.router, dependencies=_auth)
app.include_router(assets.router, dependencies=_auth)
app.include_router(cve.router, dependencies=_auth)
app.include_router(integrations.router, dependencies=_auth)
app.include_router(documents.router, dependencies=_auth)
app.include_router(audit.router, dependencies=_auth)
app.include_router(surface.router, dependencies=_auth)
app.include_router(topology.router, dependencies=_auth)
app.include_router(intel.router, dependencies=_auth)


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Loga o traceback completo (visivel em `docker compose logs api`) e
    devolve a classe+mensagem do erro no detail -> some o '500' opaco."""
    logger.error(
        "Erro nao tratado em %s %s:\n%s", request.method, request.url.path,
        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    )
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {exc}"})


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "ai_enabled": settings.ai_enabled}
