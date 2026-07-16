"""带认证与版本的最小 HTTP/RPC 工具网关验证。"""

from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

SPIKE_TOKEN = "spike-node-token"  # nosec: 仅用于非生产环境的固定测试值


class ToolCall(BaseModel):
    """一次远端工具调用的版本化请求信封。"""

    model_config = ConfigDict(extra="forbid")

    arguments: dict[str, str]
    timeout_seconds: float = Field(gt=0, le=5)


class ToolResult(BaseModel):
    """包含明确跨节点追踪标识符的响应。"""

    run_id: str
    tool_run_id: str
    result: dict[str, str]


def authenticate_node(authorization: Annotated[str | None, Header()] = None) -> str:
    """拒绝未携带独立预配节点凭据的请求。"""
    if authorization != f"Bearer {SPIKE_TOKEN}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "unauthenticated"},
        )
    return "node_spike"


def build_app() -> FastAPI:
    """构建版本化 HTTP/RPC 对比应用。"""
    app = FastAPI(title="TunnelMinion 传输方案验证")

    @app.get("/v1/capabilities", dependencies=[Depends(authenticate_node)])
    async def capabilities() -> dict[str, object]:
        return {
            "protocol": {"major": 1, "minor": 0},
            "tools": [{"name": "get_node_summary", "version": {"major": 1, "minor": 0}}],
        }

    @app.post("/v1/tools/get_node_summary:call", response_model=ToolResult)
    async def call_node_summary(
        request: ToolCall,
        run_id: Annotated[str, Header(alias="X-Run-ID")],
        tool_run_id: Annotated[str, Header(alias="X-Tool-Run-ID")],
        _caller: Annotated[str, Depends(authenticate_node)],
    ) -> ToolResult:
        async with asyncio.timeout(request.timeout_seconds):
            await asyncio.sleep(0)
            return ToolResult(
                run_id=run_id,
                tool_run_id=tool_run_id,
                result={"node_id": request.arguments["node_id"], "status": "online"},
            )

    _ = capabilities, call_node_summary
    return app
