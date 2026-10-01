from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.config import Environment, LoggingSettings, Settings, to_async_database_url

BASE = {"database_url": "postgresql://u:p@db/x", "redis_url": "redis://r/0"}


def test_async_url_uses_asyncpg_and_keeps_credentials() -> None:
    url = to_async_database_url(SecretStr("postgresql://u:p%40ss@db:5432/sentinel"))
    assert url == "postgresql+asyncpg://u:p%40ss@db:5432/sentinel"


def test_non_postgres_url_rejected() -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        to_async_database_url(SecretStr("mysql://u:p@db/x"))


def test_debug_logging_forbidden_in_production() -> None:
    with pytest.raises(ValidationError, match="DEBUG"):
        LoggingSettings(environment="production", log_level="DEBUG")


@pytest.mark.parametrize(
    ("environment", "expected"),
    [("development", "console"), ("test", "json"), ("production", "json")],
)
def test_default_log_format(environment: Environment, expected: str) -> None:
    assert LoggingSettings(environment=environment).effective_log_format == expected


def test_relative_log_path_rejected() -> None:
    with pytest.raises(ValidationError, match="absolute"):
        LoggingSettings(log_file_path=Path("logs/app.log"))


def test_trusted_proxies_parsed_from_csv() -> None:
    settings = Settings(**BASE, trusted_proxies="10.0.0.0/8, 127.0.0.1")  # type: ignore[arg-type]
    assert [str(n) for n in settings.trusted_proxy_networks] == ["10.0.0.0/8", "127.0.0.1/32"]


def test_invalid_trusted_proxy_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(**BASE, trusted_proxies="not-an-ip")  # type: ignore[arg-type]


def test_secrets_are_masked_in_repr() -> None:
    settings = Settings(**BASE)  # type: ignore[arg-type]
    assert "u:p@" not in repr(settings)


def test_empty_env_values_mean_unset() -> None:
    settings = LoggingSettings(log_format="", log_file_path="")
    assert settings.log_format is None
    assert settings.log_file_path is None
