## MODIFIED Requirements

### Requirement: Runtime 提供基础只读系统工具

Windows 与 macOS Runtime MUST 在平台支持和权限允许时提供 WireGuard 状态、监听端口、进程摘要、Docker 服务和服务可达性工具。监听工具 MUST 排除系统事实中带明确远端地址的 UDP 客户端连接，并 MUST 保留没有远端地址的 UDP 端点与 TCP 监听。权限不足或依赖缺失 MUST 作为结构化降级，而不是使整个 Runtime 崩溃。

#### Scenario: 读取 A 的 WireGuard 状态

- **WHEN** Agent 在 A 调用 WireGuard 状态工具
- **THEN** 工具返回 `HomeMac` 的接口、peer 公钥摘要、允许地址、最近握手和流量统计，且不返回任何私钥

#### Scenario: B 未运行 Docker

- **WHEN** Agent 在 B 调用 Docker 服务工具而 Docker 不可用
- **THEN** 工具返回 `dependency_unavailable`，其他端口、进程和 WireGuard 工具仍可使用

#### Scenario: UDP 客户端连接不冒充监听服务

- **WHEN** psutil 返回带远端地址的 UDP socket，或 macOS `lsof` 返回带 `->` 远端端点的 UDP 记录
- **THEN** 监听工具排除该记录，但继续返回没有远端地址的 UDP 端点和处于 `LISTEN` 状态的 TCP 端点
