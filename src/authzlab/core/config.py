"""Application settings using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "AuthZLab"
    app_version: str = "0.1.0"
    environment: Literal["development", "testing", "production"] = "development"
    debug: bool = False

    # Server
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1

    # Database
    database_url: str = Field(
        default="postgresql+psycopg://authzlab:authzlab@localhost:5432/authzlab",
        description="PostgreSQL connection URL",
    )
    database_pool_size: int = 5
    database_max_overflow: int = 10
    database_pool_timeout: int = 30

    # Security (M-E: no dead secret config; RS256 keys below are the only signing config)
    algorithm: Literal["RS256"] = "RS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    jwt_issuer: str = "authzlab"
    jwt_audience: str = "authzlab-api"
    jwt_private_key: str | None = Field(
        default=None,
        description="PEM-encoded RSA private key for JWT signing (required in production)",
    )
    jwt_public_key: str | None = Field(
        default=None,
        description="PEM-encoded RSA public key for JWT verification (required in production)",
    )
    jwt_kid: str = Field(default="dev-key-1", description="JWT key ID header")

    # Password hashing
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

    # Lab mode
    lab_mode: bool = False
    lab_allow_external: bool = False


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
