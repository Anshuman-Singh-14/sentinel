from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings
from app.core.security.ssrf import TargetUrl, parse_target_url


class HeaderTlsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        description=(
            "URL or host name to check (https:// is assumed). It must be inside the scan scope."
        ),
        max_length=2048,
        json_schema_extra={"examples": ["https://example.com/"]},
    )
    check_http_redirect: bool = Field(
        default=True,
        description="Also check whether plain http:// on port 80 redirects to HTTPS.",
    )

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        return str(parse_target_url(value, frozenset(get_settings().web_check_allowed_ports)))

    def target(self) -> TargetUrl:
        return parse_target_url(self.url, frozenset(get_settings().web_check_allowed_ports))
