from pydantic import BaseModel, ConfigDict, Field

from app.core.security.validators import DomainName


class DnsLookupParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: DomainName = Field(
        description="Domain to investigate, e.g. example.com.",
        json_schema_extra={"examples": ["example.com"], "maxLength": 253},
    )
    include_reverse: bool = Field(
        default=True,
        description="Also look up reverse DNS (PTR) names for the resolved public IP addresses.",
    )
