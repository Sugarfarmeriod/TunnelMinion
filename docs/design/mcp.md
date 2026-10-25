# MCP：让外部 Agent 直接用 TunnelMinion 的诊断工具

> 状态：已实现。

## 一句话

运行 `tunnelminion mcp`，TunnelMinion 就成了一个 MCP 服务端。Claude Code、Cursor 这类外部 Agent 可以直接调用它的只读诊断工具，比如"这台电脑上 8000 端口是什么程序""本机有哪些服务"。

## 怎么接

MCP 只走本机的标准输入输出（stdio）：外部 Agent 在本机启动 `tunnelminion mcp` 这个进程，通过它的输入输出对话。这样不开任何网络端口，也就不需要另外做登录认证。

在 Claude Code 里加一个 MCP 服务端，命令写 `tunnelminion mcp`。如果要用指定的数据目录，就加上 `--data-dir <目录>`。

## 开放了哪些工具

只开放风险等级为"只读"的工具：

| 工具 | 做什么 |
|---|---|
| `list_local_services` | 本机服务清单：服务名、入口、"是我的服务 / 隐藏"标记，和首页服务地图用的是同一份数据 |
| `list_network_listeners` | 正在监听的端口和对应进程 |
| `get_process_summary` | 进程摘要 |
| `list_docker_services` | Docker 容器 |
| `probe_service_reachability` | 探测某个地址和端口能不能连上 |
| `get_wireguard_status` | 组网状态（只读） |
| `get_node_summary` | 本机概况 |

**不开放的：**
- 委派（`delegate_to_node`）；
- 所有修复类工具；
- 任何会改变系统的操作。

开放的范围按"风险等级为只读，且不在排除名单里"判断，测试锁定了这一点。

## 边界

- 每次调用都走 Agent 用的同一套工具执行通道，所以参数校验、超时、结果大小上限和审计记录都和 Agent 一样。
- 出错时只返回安全的错误码和一句说明，不返回调用栈和内部细节。
- 标准输出只用来传 MCP 协议，日志写到标准错误。

## 验收记录（2026-10-26，Windows）

用一个独立的 MCP 客户端（官方 Python SDK 的 stdio 客户端，和 Claude Code 接入方式相同）启动 `tunnelminion mcp`，结果如下：

- 列出 7 个工具，和上表一致。
- `get_node_summary` 成功，耗时 0.03 秒。
- `probe_service_reachability` 探测 127.0.0.1:9，返回"连不上"，耗时 2 秒。
- 本机临时起了一个只监听 127.0.0.1 的测试网页。`list_local_services` 识别出它，名称取自网页标题"MCP 测试页"，耗时 5.2 秒。
- 调用未开放的 `delegate_to_node`，返回"工具未开放"错误。
