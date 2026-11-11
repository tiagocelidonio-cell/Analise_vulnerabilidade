"""Autenticacao: hash de senha (pbkdf2 da stdlib) + JWT.

Sem dependencia de bcrypt/passlib — usa hashlib.pbkdf2_hmac, robusto e nativo.
O token pode vir no header Authorization: Bearer <t> ou no query param ?token=
(este ultimo so para abrir relatorios PDF/HTML em nova aba no navegador).
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_session
from app.models import User

_ALGO = "HS256"
_ITER = 200_000


# ---------- senha ----------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)
    return f"pbkdf2_sha256${_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# ---------- token ----------
def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGO)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[_ALGO])
    except jwt.PyJWTError:
        return None


# ---------- dependencias ----------
def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.query_params.get("token")


async def get_current_user(
    request: Request, session: AsyncSession = Depends(get_session)
) -> User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(401, "Nao autenticado")
    payload = decode_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(401, "Token invalido ou expirado")
    user = await session.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(401, "Usuario inativo ou inexistente")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Requer privilegio de administrador")
    return user


async def ensure_seed_admin(session: AsyncSession) -> None:
    """Cria o admin inicial se nao houver nenhum usuario."""
    existing = await session.scalar(select(User).limit(1))
    if existing is not None:
        return
    admin = User(
        email=settings.admin_email,
        name="Administrador",
        hashed_password=hash_password(settings.admin_password),
        role="admin",
    )
    session.add(admin)
    await session.commit()
    print(
        f"[auth] Admin inicial criado: {settings.admin_email} "
        f"(senha definida em ADMIN_PASSWORD). ALTERE A SENHA!"
    )
