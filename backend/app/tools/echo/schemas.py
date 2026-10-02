from pydantic import BaseModel, ConfigDict, Field


class EchoParams(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    message: str = Field(min_length=1, max_length=500, description="Text to echo back.")
    repeat: int = Field(default=1, ge=1, le=5, description="How many times to repeat it.")
