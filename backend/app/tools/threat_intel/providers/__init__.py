"""Threat-intel providers. Each is enabled only when its API key is configured.

Adding a provider: one module with a ``Provider`` subclass, plus one line in
``PROVIDERS`` with the settings that hold its key, base URL and budget.
"""

from dataclasses import dataclass

from app.config import Settings
from app.tools.threat_intel.providers.abuseipdb import AbuseIpdbProvider
from app.tools.threat_intel.providers.base import Provider
from app.tools.threat_intel.providers.shodan import ShodanProvider
from app.tools.threat_intel.providers.virustotal import VirusTotalProvider


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    cls: type[Provider]
    key_setting: str
    url_setting: str
    budget_setting: str
    env_var: str


PROVIDERS = (
    ProviderSpec(
        AbuseIpdbProvider,
        "abuseipdb_api_key",
        "abuseipdb_base_url",
        "abuseipdb_requests_per_minute",
        "ABUSEIPDB_API_KEY",
    ),
    ProviderSpec(
        VirusTotalProvider,
        "virustotal_api_key",
        "virustotal_base_url",
        "virustotal_requests_per_minute",
        "VIRUSTOTAL_API_KEY",
    ),
    ProviderSpec(
        ShodanProvider,
        "shodan_api_key",
        "shodan_base_url",
        "shodan_requests_per_minute",
        "SHODAN_API_KEY",
    ),
)


def configured(settings: Settings) -> list[Provider]:
    """Instantiate every provider whose API key is set."""
    providers: list[Provider] = []
    for spec in PROVIDERS:
        key = getattr(settings, spec.key_setting)
        if key is None or not key.get_secret_value().strip():
            continue
        providers.append(
            spec.cls(
                key.get_secret_value().strip(),
                getattr(settings, spec.url_setting),
                getattr(settings, spec.budget_setting),
            )
        )
    return providers


def status(settings: Settings) -> list[dict[str, object]]:
    """Catalogue view: which providers exist and which are configured (never the key)."""
    enabled = {p.provider_id for p in configured(settings)}
    return [
        {
            "id": spec.cls.provider_id,
            "name": spec.cls.name,
            "configured": spec.cls.provider_id in enabled,
            "env_var": spec.env_var,
            "supports": sorted(kind.value for kind in spec.cls.supports),
        }
        for spec in PROVIDERS
    ]
