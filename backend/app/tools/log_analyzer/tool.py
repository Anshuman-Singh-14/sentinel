from app.config import get_settings
from app.core.audit.actions import AuditAction
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.log_analyzer import service, translator
from app.tools.log_analyzer.rules import get_rules
from app.tools.log_analyzer.schemas import LogAnalyzerParams

# Decompressed .gz input may be this many times the upload limit, no more
# (a small "zip bomb" cannot expand without bound).
DECOMPRESSION_FACTOR = 20


class LogAnalyzerTool(BaseTool[LogAnalyzerParams]):
    """Log File Analyzer (02-modules.md, backend tool 5). Local: no network traffic.

    Reads an uploaded file or a file inside the read-only LOG_ROOT, parses it
    line by line with a format plugin, and evaluates the YAML detection rules.
    Log contents are never logged, audited or stored, apart from short,
    sanitised samples in the evidence of a finding.
    """

    tool_id = "log_analyzer"
    name = "Log File Analyzer"
    description = (
        "Finds signs of attack in SSH auth logs and nginx/Apache access logs: password "
        "guessing, user enumeration, logins after failures, root logins, path traversal, "
        "scanners, request floods and error spikes. Upload a file or pick one from the "
        "server's log directory."
    )
    version = "1.0.0"
    category = ToolCategory.FORENSIC
    params_model = LogAnalyzerParams
    soft_time_limit = 120
    hard_time_limit = 150
    accepts_upload = True
    request_audit_action = AuditAction.LOG_ANALYSIS_REQUESTED

    @classmethod
    def max_upload_bytes(cls) -> int:
        return get_settings().log_upload_max_mb * 1024 * 1024

    async def run(self, params: LogAnalyzerParams, ctx: ToolContext) -> RawOutput:
        settings = get_settings()
        stream, size, _ = service.open_source(
            path=params.path, upload_path=ctx.upload_path, log_root=settings.log_root
        )
        with stream:
            raw = await service.analyse(
                stream,
                size=size,
                parser_choice=params.parser,
                rules=get_rules(),
                ctx=ctx,
                max_lines=settings.log_analyzer_max_lines,
                max_line_bytes=settings.log_analyzer_max_line_bytes,
                max_total_bytes=self.max_upload_bytes() * DECOMPRESSION_FACTOR,
            )
        raw["source"] = {
            "kind": "upload" if params.upload_name else "log_root",
            "name": params.upload_name or params.path,
            "bytes": size,
        }
        return raw

    def translate(self, raw: RawOutput, params: LogAnalyzerParams) -> list[Finding]:
        return translator.translate(raw)

    def target_of(self, params: LogAnalyzerParams) -> str:
        return params.upload_name or params.path
