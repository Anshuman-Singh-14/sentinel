"""Raw echo output -> findings, with text from the knowledge base."""

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Finding, FindingStatus
from app.tools.echo.schemas import EchoParams


def translate(raw: RawOutput, params: EchoParams) -> list[Finding]:
    entry = get_knowledge_base().get("echo.message_received")
    values = {"length": raw["length"], "repeat": params.repeat}
    return [
        Finding(
            item=entry.title,
            category="DIAGNOSTIC",
            status=FindingStatus.INFO,
            severity=entry.severity,
            severity_rationale=entry.severity_rationale,
            explanation=entry.render("explanation", **values),
            remediation=entry.remediation,
            evidence={"echo_count": len(raw["echoes"]), "length": raw["length"]},
            references=list(entry.references),
        )
    ]
