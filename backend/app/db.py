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


# Migracoes leves: adiciona colunas novas em bancos ja existentes (idempotente).
# Em producao recomenda-se Alembic; isto evita perda de dados entre versoes.
_MIGRATIONS = [
    "ALTER TABLE engagements ADD COLUMN IF NOT EXISTS owner_id VARCHAR",
    "ALTER TABLE engagements ADD COLUMN IF NOT EXISTS allow_intrusive BOOLEAN DEFAULT false",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS collectors JSON DEFAULT '[]'",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS phase VARCHAR DEFAULT ''",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS findings_count INTEGER DEFAULT 0",
]


async def init_db() -> None:
    """Cria as tabelas e aplica migracoes leves no boot."""
    from sqlalchemy import text

    from app import models  # noqa: F401  garante registro dos modelos

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for stmt in _MIGRATIONS:
            try:
                await conn.execute(text(stmt))
            except Exception:  # noqa: BLE001  coluna ja existe / variacao de engine
                pass
