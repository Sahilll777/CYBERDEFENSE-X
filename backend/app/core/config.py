from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # ---------------------------------------------------------
    # Application
    # ---------------------------------------------------------
    app_name: str = "CYBERDEFENSE-X"
    app_env: str = "development"
    debug: bool = False

    # ---------------------------------------------------------
    # Backend
    # ---------------------------------------------------------
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000

    # ---------------------------------------------------------
    # PostgreSQL
    # ---------------------------------------------------------
    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5433
    postgres_db: str = "cyberdefense"
    postgres_user: str = "cyberdefense"
    postgres_password: str

    # ---------------------------------------------------------
    # JWT
    # ---------------------------------------------------------
    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = Field(
        default=30,
        gt=0,
    )

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def database_url(self) -> str:
        """Build the PostgreSQL SQLAlchemy connection URL."""

        return (
            "postgresql+psycopg://"
            f"{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}"
            f"/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings instance."""

    return Settings()