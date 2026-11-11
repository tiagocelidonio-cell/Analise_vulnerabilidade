"""Rotas de autenticacao: login, perfil e gestao de usuarios (admin)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
from app.db import get_session
from app.models import User
from app.schemas import LoginIn, TokenOut, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
async def login(
    body: LoginIn, session: AsyncSession = Depends(get_session)
) -> TokenOut:
    user = await session.scalar(select(User).where(User.email == body.email))
    if user is None or not user.is_active or not verify_password(
        body.password, user.hashed_password
    ):
        raise HTTPException(401, "Credenciais invalidas")
    return TokenOut(access_token=create_access_token(user))


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: User = Depends(require_admin), session: AsyncSession = Depends(get_session)
) -> list[User]:
    rows = await session.scalars(select(User).order_by(User.created_at))
    return list(rows)


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> User:
    exists = await session.scalar(select(User).where(User.email == body.email))
    if exists is not None:
        raise HTTPException(409, "Email ja cadastrado")
    user = User(
        email=body.email,
        name=body.name,
        role=body.role if body.role in ("admin", "analyst") else "analyst",
        hashed_password=hash_password(body.password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    body: UserCreate,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Admin altera papel/senha/ativacao de um usuario."""
    u = await session.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Usuario nao encontrado")
    if body.role in ("admin", "analyst"):
        u.role = body.role
    if body.name:
        u.name = body.name
    if body.password:
        u.hashed_password = hash_password(body.password)
    await session.commit()
    await session.refresh(u)
    return u


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    if user_id == admin.id:
        raise HTTPException(400, "Nao e possivel excluir o proprio usuario")
    u = await session.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Usuario nao encontrado")
    await session.delete(u)
    await session.commit()
