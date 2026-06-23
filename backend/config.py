from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Security Findings Translator"
    app_version: str = "0.2.0"
    debug: bool = False
    environment: str = "development"

    api_prefix: str = "/api/v1"
    allowed_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    translator_model: str = "gemini-2.5-flash"
    translator_max_tokens: int = 8000

    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/sft"
    database_pool_size: int = 10

    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = 3600

    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""

    max_upload_size_mb: int = 50
    upload_dir: str = "/tmp/sft_uploads"

    rate_limit_per_minute: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
