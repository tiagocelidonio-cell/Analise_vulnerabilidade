"""Configuracao central, lida do ambiente (12-factor)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Infra
    database_url: str = "postgresql+asyncpg://vulnscope:vulnscope@db:5432/vulnscope"
    redis_url: str = "redis://redis:6379/0"

    # Evidencias
    s3_endpoint_url: str = "http://minio:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket: str = "evidence"

    # IA
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-4-8"

    # Limites de seguranca do scanner
    scan_max_concurrency: int = 200
    scan_connect_timeout: float = 2.0

    # Autenticacao
    jwt_secret: str = "change-me-in-production"
    jwt_expire_minutes: int = 720
    admin_email: str = "admin@vulnscope.local"
    admin_password: str = "changeme"

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
