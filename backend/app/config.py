"""Application settings loaded from environment variables.

Phase 0 holds only what the health/readiness checks and the Celery app need;
Phase 1 grows this into the full settings model.

Why pydantic-settings: values are validated at startup (fail fast on bad
config), and connection strings are ``SecretStr`` so they are masked in reprs,
tracebacks and logs (CLAUDE.md rule 4).
"""

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    environment: Literal["development", "test", "production"] = "development"

    # Credentials are embedded in these URLs, so they are secrets.
    database_url: SecretStr
    redis_url: SecretStr

    # Strict CORS allowlist (04-security.md section 9). Comma-separated in env.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # Every outbound check has a timeout (CLAUDE.md rule 7).
    readiness_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard(cls, value: list[str]) -> list[str]:
        # A wildcard origin combined with credentialed requests (Phase 2 cookies)
        # would let any website act as the logged-in user, so it is refused.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must be an explicit allowlist, not '*'")
        return value


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings (cached so env is parsed once)."""
    # Required fields (database_url, redis_url) are populated from the environment.
    return Settings()
