# Coordinator 集成入口与迁移约束

本清单固定 `coordinate-agent-network` 开始前的真实入口。Coordinator 只增加控制面目录与短期
身份，不替换现有 WireGuard、Gateway 数据面、模型 Provider 或操作治理。

| 维度 | 当前权威入口 | 已验证行为 | Coordinator 迁移约束 |
| --- | --- | --- | --- |
| 稳定节点身份 | `app.load_or_create_node_id`、各节点数据目录的 `node-id` | 重启后复用同一 `NodeId` | 注册必须复用该 ID；相同本机身份重试不得创建重复节点 |
| 静态 peer 配置 | `gateway.configuration.GatewayConfigurationService` 与 `gateway.json` | endpoint、工具/操作允许列表落盘，token 只进秘密存储 | 目录 peer 不能静默覆盖或删除 static peer；回滚继续使用 static token |
| Gateway 监听 | `gateway.security.GatewayBindConfig`、`macos_app.build_macos_gateway_application` | 只接受明确私有地址，默认端口 `8787` | Coordinator 不修改监听、WireGuard、路由或防火墙；首轮 B 仍为 `10.77.0.1:8787` |
| Gateway 认证与授权 | `GatewayPeerPolicy`、`GatewaySecurityPolicy`、`gateway.api.create_gateway_router` | Bearer token 转 SHA-256 摘要并常量时间比较；再检查 peer 允许列表、限流、协议和工具 | signed assertion 是并列认证方式；目标 Gateway 的本地策略始终最终裁决 |
| 远端固定客户端 | `gateway.client.FixedGatewayClient` | endpoint 与 token 由程序外注入，能力发现和调用均有超时/协议校验 | 目录只能解析已验证 endpoint；模型不得提交地址或认证材料 |
| 节点摘要预检 | Windows/macOS `NodeSummaryAdapter` 与 `get_node_summary` | 返回稳定节点、平台、模型与 WireGuard 可用性、能力数量 | 目录只用于预筛选；首次调用或目录修订变化后仍须直连复核 |
| 动态远端工具 | `agent.remote.RemoteCapabilityLoader`、`RemoteToolExecutor` | 先发现能力和节点摘要，只注册请求的只读工具，执行仍走固定 Gateway | 增加 network、状态、新鲜度、授权、平台、版本、风险和任务阶段过滤，不扩权 |
| 本地资源 API | `web.resources.create_resource_router` | `/api/resources/*` 直接调用确定性本地工具，无模型也可用 | Coordinator 离线不得阻塞本地资源；后续仅增加脱敏目录状态 |
| Windows 应用组装 | `app.build_windows_application` | 本地页面、模型、工具、记忆和操作控制独立组装 | 同步器必须独立超时/取消；不得把模型密钥、记忆或对话交给 Coordinator |
| macOS 双应用边界 | `build_macos_local_application`、`build_macos_gateway_application` | 本地页面与私网 Gateway 分离；Gateway 不暴露本地页面和 OpenAPI | Coordinator Agent API 与环回管理员 API 继续独立监听，不复用聊天或 Gateway 端口 |
| 临时服务共享 | `operation.http_sharing`、`operation.workflow`、Gateway operation 路由 | L2 操作经批准、租约、验证、到期与恢复治理 | Coordinator 不接收操作计划/结果或代理临时服务流量，不改变 `18881-18889` 的本机防火墙管理 |

## 首轮迁移不变量

- Windows A 与 macOS B 的现有 WireGuard 地址、Gateway `8787`、模型 `8082` 和静态 token 配置不变。
- Coordinator 的失败只影响目录刷新和 managed assertion 获取；本地工具、资源页、静态 peer、
  已有操作状态、撤销、租约到期和恢复继续工作。
- Coordinator 只允许节点状态、私有 Gateway endpoint、能力摘要、脱敏服务摘要、修订和脱敏审计。
- Tool/Operation 请求与响应、服务业务正文、模型请求、认证头、Gateway token、模型密钥、记忆、
  对话和 WireGuard 私钥永不经过 Coordinator。
- 本阶段只运行本机契约和密码学 spike，不连接真实 A/B，不申请或打开任何新端口。
