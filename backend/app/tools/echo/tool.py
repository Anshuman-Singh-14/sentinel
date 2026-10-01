from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.echo import service, translator
from app.tools.echo.schemas import EchoParams


class EchoTool(BaseTool[EchoParams]):
    """Trivial tool proving the plugin contract: params -> run -> translate -> ToolResult."""

    tool_id = "echo"
    name = "Echo (diagnostic)"
    description = "Echoes a message back through the standard result pipeline."
    version = "1.0.0"
    category = ToolCategory.DIAGNOSTIC
    params_model = EchoParams
    is_active = False
    soft_time_limit = 5
    hard_time_limit = 10

    async def run(self, params: EchoParams, ctx: ToolContext) -> RawOutput:
        return await service.echo(params.message, params.repeat, ctx)

    def translate(self, raw: RawOutput, params: EchoParams) -> list[Finding]:
        return translator.translate(raw, params)
