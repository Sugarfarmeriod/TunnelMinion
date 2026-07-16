# ADR 0001：MVP 使用版本化 HTTP/RPC 网关

- 状态：已接受
- 日期：2026-07-16
- Change：`deliver-ai-agent-over-existing-mesh`

## 背景

TunnelMinion 需要在现有 WireGuard 网络上完成经过认证的 A 到 B 只读工具调用。传输层必须
支持能力发现、严格 schema、取消与截止时间、有界结果、协议协商，以及通过 `run_id` 和
`tool_run_id` 进行关联追踪。

`spikes/transport` 中的验证对比了稳定版 MCP Python SDK 的 Streamable HTTP 模型和精简的
版本化 HTTP/RPC 信封。自动化测试验证了 MCP 工具发现，以及 HTTP/RPC 原型的认证、版本化
能力响应和追踪 ID 传播。

做出决策时，官方 MCP Python SDK 将 v1 标记为稳定版、v2 标记为 alpha，并计划在本次验证
结束后不久发布 v2 稳定版。MCP 认证采用 OAuth 2.1 资源服务器模型，实验性的 MCP Tasks
提供异步任务与取消语义。这些互操作能力具有价值，但超出了 MVP 中两个显式预配节点和
有界请求的需求。

参考资料：

- [官方 MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP 认证规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Tasks 规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)

## 决策

MVP 使用基于 ASGI 实现的无状态版本化 HTTP/RPC 网关，并提供：

- 经过认证的 `GET /v1/capabilities`；
- 精确且带版本的工具调用路由；
- 独立于 WireGuard 密钥的应用层节点凭据；
- 请求截止时间，以及客户端断开或本地 run 取消时的取消机制；
- 明确的响应字节限制和结构化错误码；
- 每次调用携带 `run_id`、`tool_run_id`、调用节点、执行节点和工具版本。

业务工具 schema 继续使用与传输层无关的 `ToolDefinition`。MCP v2 生态稳定后可以增加 MCP
适配器，而不需要重写平台工具或 Agent 策略。

## 对比

| 关注点 | MCP Streamable HTTP | 版本化 HTTP/RPC |
|---|---|---|
| 能力发现 | 内置 `tools/list`，这是 MCP 最明显的优势 | 通过现有 `ToolDefinition` 提供精简显式端点 |
| 结构化工具 | 内置 schema 与结构化输出 | 直接使用 Pydantic 请求/响应模型 |
| 认证 | 基于标准的 OAuth 资源服务器；对两个预配节点较重 | 预配节点凭据和允许列表直接符合 MVP |
| 取消 | 通知机制及仍处于实验阶段的 Tasks 语义 | 截止时间和应用取消 token 映射到单次请求 |
| 可观察性 | 提供日志/通知；仍需约定 TunnelMinion 关联 ID | 关联头和审计信封属于强制的一等字段 |
| 版本稳定性 | Python SDK 即将切换主版本 | 由产品拥有并控制的精简接口 |
| 外部互操作 | 优秀 | TunnelMinion 专用 |

## 影响

TunnelMinion 需要自行维护少量网关协议代码，并且无法立即让任意 MCP 客户端直接连接节点。
作为交换，初期安全模型、取消行为、错误、审计 ID 和版本协商可以保持明确且可测试。协议
必须保持窄边界：只能暴露已注册工具，不得演变为通用远程 API。

## 重新评估条件

当 MCP Python SDK v2 已稳定、服务账户认证具有明确支持路径、任务取消不再是实验功能，
并且出现真实的外部 MCP 客户端需求时，重新评估 MCP 适配器。除非能继续强制执行全部
TunnelMinion 安全不变量，否则不能仅为了互操作性替换 MVP 网关。
