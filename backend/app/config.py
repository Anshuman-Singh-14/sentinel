"""Application settings loaded from environment variables.

Why pydantic-settings: values are validated at startup (fail fast on bad
config), and connection strings are ``SecretStr`` so they are masked in reprs,
tracebacks and logs (CLAUDE.md rule 4).

The settings are split by consumer so each container receives only the secrets
it needs:

* ``LoggingSettings``: shared by every process.
* ``Settings``: api and worker. Connects as the least-privilege ``sentinel_app`` role.
* ``MigrationSettings``: the one-shot ``migrate`` container only. Connects as
  the schema owner, whose password never reaches the api or worker.
"""

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import make_url

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
LogFormat = Literal["json", "console"]


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class LoggingSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    environment: Environment = "development"

    log_level: LogLevel = "INFO"
    # Unset means: pretty console output in development, JSON everywhere else.
    log_format: LogFormat | None = None
    # Optional rotating JSON log file, in addition to stdout.
    log_file_path: Path | None = None
    log_retention_days: int = Field(default=14, ge=1, le=365)
    # Oversized values (raw banners, response bodies) are truncated in logs.
    log_max_field_length: int = Field(default=2048, ge=128, le=65536)

    @property
    def effective_log_format(self) -> LogFormat:
        if self.log_format is not None:
            return self.log_format
        return "console" if self.environment == "development" else "json"

    @field_validator("log_format", "log_file_path", mode="before")
    @classmethod
    def _empty_means_unset(cls, value: object) -> object:
        # Compose passes `${VAR:-}` as an empty string when the variable is unset.
        return None if value == "" else value

    @field_validator("log_file_path")
    @classmethod
    def _absolute_log_path(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("LOG_FILE_PATH must be an absolute path")
        return value

    @model_validator(mode="after")
    def _no_debug_in_production(self) -> Self:
        # DEBUG logs can include request/response detail that production
        # must not retain (03-logging-audit.md section 3).
        if self.environment == "production" and self.log_level == "DEBUG":
            raise ValueError("LOG_LEVEL=DEBUG is not allowed in production")
        return self


class Settings(LoggingSettings):
    # Credentials are embedded in these URLs, so they are secrets.
    database_url: SecretStr
    redis_url: SecretStr

    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=5, ge=0, le=50)
    database_pool_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    database_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    # Also set on the DB role. Repeated here as defence in depth.
    database_statement_timeout_ms: int = Field(default=30_000, ge=100, le=600_000)

    # Strict CORS allowlist (04-security.md section 9). Comma-separated in env.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # Reverse proxies whose X-Forwarded-For header is believed. Comma-separated
    # IPs/CIDRs. Empty means: never trust X-Forwarded-For (03-logging-audit.md section 2).
    trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Every outbound check has a timeout (CLAUDE.md rule 7).
    readiness_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    # --- Authentication and sessions (03-logging-audit.md section 1, ADR 0003) ---
    # Short-lived access token: bounds how long a stolen cookie stays useful.
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=60)
    # The refresh token expires after this much inactivity...
    refresh_token_idle_hours: int = Field(default=12, ge=1, le=168)
    # ...and every session ends after this long, however active it is.
    session_absolute_hours: int = Field(default=24, ge=1, le=720)
    # Secure cookies are only sent over HTTPS (browsers also accept them on
    # http://localhost). Disabling is a dev-only escape hatch for Safari and is
    # refused in production.
    cookie_secure: bool = True

    # Account lockout: after N consecutive failures the account locks, with the
    # duration doubling on each further failure up to the maximum.
    login_max_failures: int = Field(default=5, ge=1, le=100)
    lockout_base_seconds: int = Field(default=60, ge=1, le=3600)
    lockout_max_seconds: int = Field(default=900, ge=1, le=86_400)
    # Per-IP limit on login and refresh attempts. Stops password spraying
    # across many accounts, which per-account lockout alone cannot.
    auth_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)

    # Security alerting (03-logging-audit.md section 7).
    alert_failed_login_threshold: int = Field(default=5, ge=1, le=1000)
    alert_window_minutes: int = Field(default=10, ge=1, le=1440)

    # Tool runs (Phase 5). Quotas bound how much load one account can create.
    run_rate_limit_per_minute: int = Field(default=20, ge=1, le=1000)
    max_active_runs_per_user: int = Field(default=3, ge=1, le=100)
    # Raw tool output stored per run; larger output is replaced by a notice.
    max_raw_output_bytes: int = Field(default=1_000_000, ge=10_000, le=20_000_000)
    # Single-use WebSocket tickets (threat model T12).
    ws_ticket_ttl_seconds: int = Field(default=30, ge=5, le=300)

    # DNS tool. Explicit upstream resolvers instead of the container's resolver:
    # Docker's embedded DNS (127.0.0.11) would answer for internal service names
    # (postgres, redis), exposing infrastructure through the tool. Empty means
    # use the system resolver (for networks that block public DNS).
    dns_nameservers: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["1.1.1.1", "9.9.9.9"]
    )
    dns_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    dns_lifetime_seconds: float = Field(default=6.0, gt=0, le=60)

    # Scope policy (Phase 6, ADR 0007). Infra subnets are always denied to
    # active tools; the default allow list is loopback plus the lab network.
    scope_infra_subnets: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["10.231.0.0/24", "10.231.1.0/24", "10.231.2.0/24"]
    )
    scope_default_allow: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128", "10.231.10.0/24"]
    )
    # Bump to make every user re-acknowledge after the statement text changes.
    authorization_statement_version: int = Field(default=1, ge=1)
    run_rate_limit_per_hour: int = Field(default=200, ge=1, le=10_000)

    # Port scanner.
    port_scan_max_ports: int = Field(default=1024, ge=1, le=65_535)
    port_scan_concurrency: int = Field(default=100, ge=1, le=500)
    port_scan_connect_timeout_seconds: float = Field(default=1.0, gt=0, le=10)
    port_scan_banner_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    # NVD CVE API 2.0. The key only raises the rate limit (5 -> 50 requests per
    # 30 s); without one the scanner still works, just with slower enrichment.
    nvd_api_key: SecretStr | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_timeout_seconds: float = Field(default=15.0, gt=0, le=60)
    nvd_cache_hours: int = Field(default=24, ge=1, le=720)

    _split_cors = field_validator("cors_origins", mode="before")(_split_csv)
    _split_proxies = field_validator("trusted_proxies", mode="before")(_split_csv)
    _split_nameservers = field_validator("dns_nameservers", mode="before")(_split_csv)
    _split_infra = field_validator("scope_infra_subnets", mode="before")(_split_csv)
    _split_allow = field_validator("scope_default_allow", mode="before")(_split_csv)

    @field_validator("scope_infra_subnets", "scope_default_allow")
    @classmethod
    def _valid_cidrs(cls, value: list[str]) -> list[str]:
        for entry in value:
            ipaddress.ip_network(entry, strict=False)
        return value

    @field_validator("nvd_api_key", mode="before")
    @classmethod
    def _empty_key_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("dns_nameservers")
    @classmethod
    def _nameservers_are_ips(cls, value: list[str]) -> list[str]:
        for entry in value:
            ipaddress.ip_address(entry)  # raises ValueError if not an IP literal
        return value

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard(cls, value: list[str]) -> list[str]:
        # A wildcard origin combined with credentialed requests (Phase 2 cookies)
        # would let any website act as the logged-in user, so it is refused.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must be an explicit allowlist, not '*'")
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_networks(cls, value: list[str]) -> list[str]:
        for entry in value:
            ipaddress.ip_network(entry, strict=False)  # raises ValueError if invalid
        return value

    @model_validator(mode="after")
    def _secure_cookies_in_production(self) -> Self:
        if self.environment == "production" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE=false is not allowed in production")
        if self.lockout_max_seconds < self.lockout_base_seconds:
            raise ValueError("LOCKOUT_MAX_SECONDS must be >= LOCKOUT_BASE_SECONDS")
        return self

    @property
    def trusted_proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(entry, strict=False) for entry in self.trusted_proxies]


class MigrationSettings(LoggingSettings):
    migration_database_url: SecretStr


def to_async_database_url(url: SecretStr) -> str:
    """Return the DSN with the asyncpg driver selected (``postgresql+asyncpg://``).

    The environment holds a plain ``postgresql://`` URL so that the same value
    works with psql and other tools.
    """
    parsed = make_url(url.get_secret_value())
    if parsed.get_backend_name() != "postgresql":
        raise ValueError("Only PostgreSQL database URLs are supported")
    return parsed.set(drivername="postgresql+asyncpg").render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings (cached so env is parsed once)."""
    # Required fields (database_url, redis_url) are populated from the environment.
    return Settings()
