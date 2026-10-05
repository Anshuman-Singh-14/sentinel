"""Log analyzer parameters, validated at the API boundary (CLAUDE.md rule 3).

Two sources, exactly one per run:

* ``path``: a file inside the server's read-only ``LOG_ROOT``. Checked here
  for obvious traversal (fast, clear 422) and again, authoritatively, by
  ``PathGuard`` in the worker.
* an upload: ``upload_name`` is filled in by the upload route with the
  uploaded file's display name. It is marked read-only in the schema, so the
  generated form does not show it; the file itself never travels in params.
"""

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.security.paths import PathRejected, check_relative_path

ParserChoice = Literal["auto", "auth_log", "nginx_access"]


class LogAnalyzerParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        default="",
        max_length=255,
        title="File on the server",
        description=(
            "A log file inside the server's log directory (LOG_ROOT), e.g. auth.log or "
            "nginx/access.log. Leave empty when you upload a file instead."
        ),
        examples=["auth.log"],
    )
    parser: ParserChoice = Field(
        default="auto",
        title="Log format",
        description="auto detects the format from the first lines of the file.",
    )
    upload_name: str = Field(
        default="",
        max_length=255,
        json_schema_extra={"readOnly": True},
        description="Set by the server for uploaded files.",
    )

    @field_validator("path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        if not value:
            return value
        try:
            return check_relative_path(value)
        except PathRejected as exc:
            # Pydantic turns ValueError into a field-level 422; anything else
            # would escape as a 500.
            raise ValueError(exc.message) from None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> Self:
        if bool(self.path) == bool(self.upload_name):
            raise ValueError("Choose a file on the server or upload one (not both).")
        return self
