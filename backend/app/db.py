"""Engine e sessao assincrona do SQLAlchemy."""
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# Desliga o cache de prepared statements do asyncpg: rodamos ALTER TYPE/ALTER
# TABLE no boot (migracoes leves), e o cache fica INVALIDO apos mudanca de
# schema -> "cached statement plan is invalid" / erros de enum (500). Sem cache,
# cada query e replanejada e sempre valida. (So aplica ao driver asyncpg.)
_connect_args = {}
if settings.database_url.startswith("postgresql+asyncpg"):
    _connect_args = {"statement_cache_size": 0}

engine = create_async_engine(
    settings.database_url, echo=False, pool_pre_ping=True,
    connect_args=_connect_args,
)
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
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS summary VARCHAR DEFAULT ''",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN DEFAULT false",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS pause_requested BOOLEAN DEFAULT false",
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS profile VARCHAR DEFAULT 'full'",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS signature VARCHAR DEFAULT ''",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS times_seen INTEGER DEFAULT 1",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ",
]

# Valores novos do enum nativo do Postgres precisam entrar FORA de transacao
# (autocommit). Idempotente via IF NOT EXISTS. Em bancos nao-PG, o except ignora.
_ENUM_MIGRATIONS = [
    "ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'paused'",
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

    # ALTER TYPE ... ADD VALUE nao roda dentro de transacao -> autocommit.
    for stmt in _ENUM_MIGRATIONS:
        try:
            async with engine.connect() as conn:
                conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
                await conn.execute(text(stmt))
        except Exception:  # noqa: BLE001  valor ja existe / engine sem enum nativo
            pass
