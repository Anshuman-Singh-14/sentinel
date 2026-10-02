from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from app.config import get_settings
from app.core.security.validators import HostTarget
from app.tools.port_scanner.ports import PRESETS, parse_ports


class PortScanParams(BaseModel):
    """Plain types only (no Optional, no nested enums), so the frontend's
    schema-driven form can render every field."""

    model_config = ConfigDict(extra="forbid")

    target: HostTarget = Field(
        description="Host name or IP address to scan. It must be inside the scan scope.",
        json_schema_extra={"examples": ["lab-banners"], "maxLength": 253},
    )
    preset: Literal["top-100", "top-1000", "web", "custom"] = Field(
        default="top-100",
        description="Which ports to scan. Choose 'custom' to list ports yourself.",
    )
    ports: str = Field(
        default="",
        max_length=500,
        description="Only for 'custom': ports and ranges, e.g. 22,80,443,8000-8100.",
    )
    grab_banners: bool = Field(
        default=True,
        description="Read what each open service announces (and send HEAD / on HTTP ports).",
    )
    cve_lookup: bool = Field(
        default=True,
        description="Look up known CVEs in the NVD for products identified from banners.",
    )

    @field_validator("ports")
    @classmethod
    def _ports_for_custom(cls, value: str, info: ValidationInfo) -> str:
        if info.data.get("preset") == "custom":
            parse_ports(value, get_settings().port_scan_max_ports)  # raises ValueError
        elif value.strip():
            raise ValueError("Ports are only used with the 'custom' preset.")
        return value.strip()

    def port_list(self) -> list[int]:
        limit = get_settings().port_scan_max_ports
        if self.preset == "custom":
            return parse_ports(self.ports, limit)
        ports = PRESETS[self.preset]
        if len(ports) > limit:
            raise ValueError(f"The {self.preset} preset exceeds the {limit}-port limit.")
        return ports
