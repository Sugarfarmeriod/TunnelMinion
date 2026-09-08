## Context

主线现已具备确定性快照、incident 触发、单 Agent 本机调查、Overview、固定评测和人工审批操作闭环。跨节点基础设施也已存在：`FixedGatewayClient`、`RemoteCapabilityLoader`、目标身份预检、只读能力过滤、关联审计和显式 static peer 配置。缺口位于两者之间：`IncidentInvestigator` 只为 `local_observation` 选择本机 registry/runtime，其他来源始终得到空工具集；工具上下文还把 caller 与 execution 都写成 incident 目标节点。

当前正式 A/B 是 Windows A 请求、macOS B 提供独立私网 Gateway。生产 macOS Gateway 的 Coordinator-managed 授权投影尚未接入常规生命周期，因此本阶段以用户已经明确配置的 static peer 作为实际授权边界；Coordinator/聚合快照只负责产生远端目标，不因此授予调用权限。

## Goals / Non-Goals

**Goals:**

- 让远端 service incident 使用目标 Gateway 的实时只读证据完成同一个假设—工具—证据—停止循环。
- 保持 caller 为当前产品节点、execution 为 incident 目标节点，并使公开轨迹和两端审计可由 `run_id`/`tool_run_id` 对应。
- 在模型看到工具前完成 static peer 授权、Gateway 认证、目标节点摘要和实时能力复核。
- 用固定远端场景、Windows/macOS 平台回执和一次最终 Qwen 运行冻结可比较指标。
- 所有验证只使用固定数据、临时目录和自有临时进程；真实 A/B 验收只读使用既有网络，不改变网络或生产服务。

**Non-Goals:**

- 不新增 Windows Gateway 产品入口、Linux、Provider、relay、自动组网或 managed Gateway 授权投影。
- 不改变 WireGuard、防火墙、路由、DNS、现有 8080/8787 进程或任何业务服务。
- 不让模型选择 endpoint、认证材料、任意参数、Shell/Python 或写工具。
- 不改变 Incident → Operation 的人工确认、目标授权、验证与回滚语义。

## Decisions

### 1. 在 Incident Agent 前增加一个目标工具准备边界

`IncidentInvestigator` 接收当前 `local_node_id` 和可选的远端工具准备器。准备器只接收固定目标 node ID、程序生成的 `ToolCallContext` 和事件允许的候选工具；返回现有 `PreparedRemoteAgentTools`，因此调查循环继续复用同一 registry/executor 合同。

本机事件仍使用本机 registry/runtime。只有目标不是当前节点、来源不是 `local_observation`、事件不是 stale/offline 且存在远端证据路径时才准备远端工具。没有准备器或准备失败时不暴露任何本机/远端工具，并确定性地以证据不足收口。

否决在 Agent 内直接创建 HTTP client：这会混合模型编排、凭据读取和远端策略，也会重复现有 `RemoteCapabilityLoader`。

### 2. 以显式 static peer 作为本阶段生产授权来源

在 `GatewayConfigurationService` 增加只读 peer 解析：按稳定 node ID 读取 endpoint、本机保存的独立 Gateway token 和允许工具交集。共享准备器再使用 `FixedGatewayClient` 与 `RemoteCapabilityLoader` 完成认证、`get_node_summary` 身份核验、协议/风险/平台过滤和远端执行。

Coordinator 或聚合快照中的 node ID 本身不产生权限；目标必须同时存在于本机显式 peer 配置。生产 managed assertion 路径需要 Gateway 侧持久化授权投影和独立生命周期，当前代码与真实部署均未具备，混入本阶段会扩大为另一项网络认证迁移。

### 3. 远端证据路径只包含目标节点能证明的事实

目标摘要是每次远端准备的强制预检，并作为带 `tool_run_id` 的第一项公开证据进入上下文。service added 使用摘要、监听与进程；service removed 使用摘要、进程与 Docker；local-only 使用摘要与监听；remote-unreachable 使用摘要、监听与进程。node-offline 和 state-stale 不尝试连接已声明离线/陈旧的目标。

远端路径不调用请求节点的本机工具，也不把在目标节点执行的 reachability probe 冒充为请求端可达性。请求端主动探测若未来确有产品价值，应以明确双来源证据另建需求。

### 4. 远端调用失败关闭且没有确定性 fallback

有远端工具时，Runtime 仍按信息缺口每轮只暴露一个或一组相关候选，并允许一次模型合同纠正。纠正后仍不选择工具、目标能力缺失、身份不符、认证失败、超时或工具输出不可用时，调查保存已有轨迹并停止为 `insufficient_evidence`。确定性 fallback 继续只适用于本机 `local_observation`，不会替模型触发额外远端调用。

### 5. 在现有 incident 评测中增加远端执行维度

固定数据集升级一个版本，为场景声明来源和目标平台；本机场景保持默认值。远端场景通过内存凭据与 ASGI Gateway 运行真实 Gateway 路由、认证、能力发现、Tool Runtime 和 Incident Investigator，不访问真实机器状态。报告新增执行范围、请求/目标平台、预检和远端安全指标，并保持原六项核心指标可比较。

真实 A/B 只在全部确定性门禁通过后运行：Windows A 调用 macOS B 的自有临时 Gateway/数据目录和临时非生产端口，执行固定只读场景，前后只读核对生产端口与网络状态并清理自有资源。若需要 UAC、sudo、防火墙、路由或现有进程变更，立即停止，不以降级结果冒充真机通过。

### 6. 冻结一份可复核而非挑选的最终基线

冻结清单绑定被评测实现提交、数据集内容哈希、Prompt 内容哈希、六个工具版本、模型/Provider、Windows/macOS 回执、真实 A/B 回执和质量/安全门槛。Qwen 只在确定性、平台和 A/B 门禁通过后运行一次；若重复出现已确认的内存失败，才按用户授权使用 DeepSeek V4 Flash，并在报告中保留实际模型身份，不能把两者结果混为同一基线。

## Risks / Trade-offs

- [static peer 仍需人工预配] → 复用当前 A/B 已部署且可撤销的最窄授权；managed Gateway 授权投影有独立需求时另建阶段。
- [目标 Gateway 可达但业务服务不可达时仍可能证据不足] → 只报告目标监听/进程事实，不用模型常识补写请求端网络事实。
- [远端摘要预检增加一次调用] → 它是身份与平台核验，不计为模型误选工具，但计入总调用和延迟。
- [真实 A/B 环境可能临时不可用] → 保留隔离回归为可重复门禁；真机项不满足时阶段不宣称完成，也不触碰生产配置求通过。
- [数据集升级会改变聚合指标分母] → 冻结报告同时保存逐场景结果、数据集哈希和旧六项定义，禁止跨数据集只比较单个百分比。

## Migration Plan

1. 先加入规格、远端准备与调查单元测试；默认无 peer 时保持安全停止。
2. 接入 Windows/macOS 本地应用，运行完整 Python、前端与 OpenSpec 门禁。
3. 生成双平台隔离回执和真实 A/B 只读回执，确认自有进程/目录已清理且生产状态不变。
4. 在冻结候选提交上运行一次最终模型评测，生成指标清单后提交证据。
5. 独立只读审计通过后合并；回滚只需撤销本阶段代码，既有 static peer、incident 数据和操作记录无需迁移。

## Open Questions

无。managed Gateway 授权投影和请求端主动探测明确留待独立价值证据，不阻塞本阶段。
