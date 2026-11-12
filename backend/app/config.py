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

    # Google Programmable Search (dorks reais). Sem chave -> so checklist.
    # Crie em https://programmablesearchengine.google.com (CX) e
    # https://developers.google.com/custom-search/v1/overview (API key).
    google_cse_key: str = ""
    google_cse_cx: str = ""
    google_cse_max_per_dork: int = 10

    # Base local de CVE: bundle oficial (CVE List JSON 5.0) para import local.
    # Default = arquivo oficial completo do projeto CVE (cve.org / CVEProject).
    # URL estavel do repositorio oficial (grande ~1GB; roda sob demanda).
    cve_feed_url: str = (
        "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    )
    # Atualizacao automatica da base (horas). 0 = desligada (so manual).
    cve_update_interval_hours: int = 0

    @property
    def google_cse_enabled(self) -> bool:
        return bool(self.google_cse_key and self.google_cse_cx)

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
