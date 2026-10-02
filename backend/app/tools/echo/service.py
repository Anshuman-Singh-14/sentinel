"""Echo logic: pure async, no framework imports (the per-tool convention)."""

from app.engine.base_tool import RawOutput, ToolContext


async def echo(message: str, repeat: int, ctx: ToolContext) -> RawOutput:
    echoes: list[str] = []
    for index in range(repeat):
        await ctx.raise_if_cancelled()
        echoes.append(message)
        await ctx.report_progress(round((index + 1) / repeat * 100), f"echo {index + 1}/{repeat}")
    return {"echoes": echoes, "length": len(message)}
