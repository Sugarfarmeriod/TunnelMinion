"""使用稳定版 v1 Python SDK 的最小 MCP 能力发现验证。"""

from mcp.server.fastmcp import FastMCP


def build_server() -> FastMCP:
    """构建包含一个结构化工具的无状态 Streamable HTTP MCP 服务器。"""
    server = FastMCP(
        "TunnelMinion 传输方案验证",
        stateless_http=True,
        json_response=True,
    )

    @server.tool()
    async def get_node_summary(node_id: str) -> dict[str, str]:
        """返回仅用于验证 MCP 工具 schema 的固定元数据。"""
        return {"node_id": node_id, "status": "online"}

    _ = get_node_summary
    return server


async def discover_tool_names(server: FastMCP) -> list[str]:
    """在不打开套接字的情况下验证 MCP 内置的 tools/list 等价能力。"""
    tools = await server.list_tools()
    return [tool.name for tool in tools]
