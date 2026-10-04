from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, WithJsonSchema, field_validator

from app.tools.threat_intel.indicators import (
    MAX_INDICATORS,
    Indicator,
    classify,
    split_indicators,
)

# A list in the API and in playbooks (``{{ steps.dns.resolved_ips }}``); a
# plain text field in the generated form, split on commas, spaces or newlines.
IndicatorList = Annotated[
    list[str],
    BeforeValidator(split_indicators),
    WithJsonSchema(
        {
            "type": "string",
            "title": "Indicators",
            "maxLength": 6000,
            "description": (
                "IP addresses, domains or file hashes (MD5, SHA-1, SHA-256), separated by "
                f"commas or new lines. At most {MAX_INDICATORS}."
            ),
            "examples": ["198.51.100.7, example.com"],
        }
    ),
]


class ThreatIntelParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: IndicatorList = Field(min_length=1, max_length=MAX_INDICATORS)

    @field_validator("indicators")
    @classmethod
    def _valid_and_unique(cls, value: list[str]) -> list[str]:
        seen: dict[str, None] = {}
        for raw in value:
            seen.setdefault(classify(raw).value, None)
        return list(seen)

    def parsed(self) -> list[Indicator]:
        return [classify(value) for value in self.indicators]
