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
import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import make_url

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
LogFormat = Literal["json", "console"]


FIM_ROOT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
FIM_MAX_ROOTS = 10


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
        default_factory=lambda: [
            "10.231.0.0/24",
            "10.231.1.0/24",
            "10.231.2.0/24",
            "10.231.3.0/24",
            "10.231.4.0/24",
        ]
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

    # Header & TLS checker (SSRF guard: 04-security.md section 3).
    web_check_allowed_ports: Annotated[list[int], NoDecode] = Field(
        default_factory=lambda: [80, 443, 8000, 8008, 8080, 8443, 8888]
    )
    web_check_max_redirects: int = Field(default=5, ge=0, le=10)
    web_check_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    web_check_max_body_bytes: int = Field(default=262_144, ge=1024, le=5_000_000)

    # NVD CVE API 2.0. The key only raises the rate limit (5 -> 50 requests per
    # 30 s); without one the scanner still works, just with slower enrichment.
    nvd_api_key: SecretStr | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_timeout_seconds: float = Field(default=15.0, gt=0, le=60)
    nvd_cache_hours: int = Field(default=24, ge=1, le=720)

    # Threat intelligence (Phase 8). Each provider is enabled only when its key
    # is set; with no key at all the tool reports itself unavailable. Keys are
    # SecretStr: never logged, never returned by the API.
    abuseipdb_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    shodan_base_url: str = "https://api.shodan.io"
    # Per-provider request budgets (a Redis window shared by all workers). The
    # defaults sit under each provider's free tier: VirusTotal's public API
    # allows 4 requests a minute.
    abuseipdb_requests_per_minute: int = Field(default=30, ge=1, le=1000)
    virustotal_requests_per_minute: int = Field(default=4, ge=1, le=1000)
    shodan_requests_per_minute: int = Field(default=30, ge=1, le=1000)
    threat_intel_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    threat_intel_cache_hours: int = Field(default=6, ge=1, le=168)

    # Uploads and the log analyzer (Phase 10, ADR 0014). The API streams an
    # uploaded file into `upload_dir` (a volume shared with the worker) under a
    # name derived from the run id, never from user input. The worker deletes it
    # after the run. `log_root` is the read-only directory of server logs the
    # analyzer may open; empty disables that source.
    upload_dir: Path = Path("/data/uploads")
    upload_timeout_seconds: int = Field(default=120, ge=5, le=3600)
    log_root: Path | None = Path("/data/logs")
    log_upload_max_mb: int = Field(default=50, ge=1, le=1024)
    log_analyzer_max_lines: int = Field(default=2_000_000, ge=1000, le=50_000_000)
    log_analyzer_max_line_bytes: int = Field(default=8192, ge=256, le=1_000_000)

    # File integrity monitor (Phase 11, ADR 0015). Named roots, `name=/abs/path`
    # comma-separated: users pick a root by name, so server paths never reach
    # the browser. Only the worker mounts them (read-only); the API needs the
    # names to validate parameters. Empty disables both FIM tools.
    fim_roots: Annotated[dict[str, Path], NoDecode] = Field(
        default_factory=lambda: {"demo": Path("/data/fim/demo")}
    )
    fim_max_files: int = Field(default=20_000, ge=10, le=200_000)
    fim_max_file_mb: int = Field(default=100, ge=1, le=10_240)
    fim_max_total_mb: int = Field(default=2048, ge=1, le=102_400)

    # Optional observability profile (ADR 0016). /metrics exists only when a
    # token is set; Prometheus presents it as a bearer token. Values from the
    # API's worker processes are kept in this private directory and summed
    # per scrape (uvicorn --workers > 1 in production).
    metrics_token: SecretStr | None = None
    # Created 0700 by app.core.metrics; /tmp is a private tmpfs in production.
    metrics_multiproc_dir: Path = Path("/tmp/sentinel-metrics")  # noqa: S108  # nosec B108

    # Reports (Phase 13). Rendering runs in a worker; these bound its cost.
    report_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    max_active_reports_per_user: int = Field(default=3, ge=1, le=100)
    report_max_bytes: int = Field(default=20_000_000, ge=100_000, le=100_000_000)
    report_render_timeout_seconds: int = Field(default=60, ge=5, le=600)
    # Admin audit-trail export: rows per file (newest first).
    audit_export_max_rows: int = Field(default=10_000, ge=100, le=100_000)

    _split_cors = field_validator("cors_origins", mode="before")(_split_csv)
    _split_proxies = field_validator("trusted_proxies", mode="before")(_split_csv)
    _split_nameservers = field_validator("dns_nameservers", mode="before")(_split_csv)
    _split_infra = field_validator("scope_infra_subnets", mode="before")(_split_csv)
    _split_allow = field_validator("scope_default_allow", mode="before")(_split_csv)
    _split_web_ports = field_validator("web_check_allowed_ports", mode="before")(_split_csv)

    @field_validator("web_check_allowed_ports")
    @classmethod
    def _valid_ports(cls, value: list[int]) -> list[int]:
        if not value or any(not 1 <= p <= 65535 for p in value):
            raise ValueError("WEB_CHECK_ALLOWED_PORTS must list ports between 1 and 65535")
        return value

    @field_validator("log_root", mode="before")
    @classmethod
    def _empty_log_root_disables(cls, value: object) -> object:
        # Without this, LOG_ROOT="" would parse as Path("."): the app directory.
        return None if value == "" else value

    @field_validator("log_root", "upload_dir")
    @classmethod
    def _absolute_dirs(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("LOG_ROOT and UPLOAD_DIR must be absolute paths")
        return value

    @field_validator("fim_roots", mode="before")
    @classmethod
    def _parse_fim_roots(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        roots: dict[str, str] = {}
        for item in (part.strip() for part in value.split(",")):
            if not item:
                continue
            name, sep, path = item.partition("=")
            if not sep:
                raise ValueError("FIM_ROOTS entries must look like name=/absolute/path")
            if name.strip() in roots:
                raise ValueError(f"FIM_ROOTS names a root twice: {name.strip()!r}")
            roots[name.strip()] = path.strip()
        return roots

    @field_validator("fim_roots")
    @classmethod
    def _valid_fim_roots(cls, value: dict[str, Path]) -> dict[str, Path]:
        if len(value) > FIM_MAX_ROOTS:
            raise ValueError(f"FIM_ROOTS may name at most {FIM_MAX_ROOTS} roots")
        for name, path in value.items():
            if not FIM_ROOT_NAME_RE.fullmatch(name):
                raise ValueError(f"FIM root name {name!r} must match {FIM_ROOT_NAME_RE.pattern}")
            if not path.is_absolute():
                raise ValueError(f"FIM root {name!r} must be an absolute path")
        return value

    @field_validator("scope_infra_subnets", "scope_default_allow")
    @classmethod
    def _valid_cidrs(cls, value: list[str]) -> list[str]:
        for entry in value:
            ipaddress.ip_network(entry, strict=False)
        return value

    @field_validator(
        "nvd_api_key",
        "abuseipdb_api_key",
        "virustotal_api_key",
        "shodan_api_key",
        "metrics_token",
        mode="before",
    )
    @classmethod
    def _empty_key_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("metrics_token")
    @classmethod
    def _strong_metrics_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError("METRICS_TOKEN must be at least 32 characters (or empty to disable)")
        return value

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
