"""Engine e sessao assincrona do SQLAlchemy."""
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncIterator[AsyncSession]:
    """Dependencia FastAPI: uma sessao por request."""
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    """Cria as tabelas no boot (skeleton). Em producao: trocar por Alembic."""
    from app import models  # noqa: F401  garante registro dos modelos

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
