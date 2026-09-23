## ADDED Requirements

### Requirement: Harness 必须持久化版本化调查状态

系统 SHALL 为每次受支持的 incident 保存 `InvestigationState`，至少包含 Skill ID/版本、当前阶段、模型与工具预算计数、已尝试步骤、成功证据、公开 facts、unknowns、停止原因和更新时间。状态 MUST 与 incident 原子保存且不得包含凭据、隐藏思维链或未经界定的原始系统正文。

#### Scenario: 工具成功后 Runtime 重启
- **WHEN** 一个 Skill 证据步骤已经成功保存，调查在生成终态前被标记为 `interrupted`
- **THEN** 显式恢复 SHALL 复用该步骤的证据和公开 facts，不重复执行该步骤，并继续处理剩余证据

#### Scenario: 工具结果尚未成功保存时中断
- **WHEN** Runtime 在工具调用完成前中断且没有保存成功步骤
- **THEN** 恢复 SHALL 将该要求视为未覆盖，并 MAY 在新 run 的预算内重新尝试，不得把不确定调用视为成功

### Requirement: Skill 必须声明证据而不得执行操作

每个 Investigation Skill MUST 提供稳定的 ID 与版本、事件匹配条件、适用拓扑/平台、语义证据要求、允许工具及执行位置、确认与 unknown 判定、失败处理和输出约束。Skill MUST NOT 执行工具、保存状态、授予权限、直接调用模型或包含写操作。

#### Scenario: 加载 service.local-only
- **WHEN** Windows 请求端收到目标为 macOS 的 `local_only` service incident
- **THEN** Harness SHALL 选择版本化 `service.local-only` Skill，并把 Skill ID/版本写入状态、trace 和评测结果

#### Scenario: 事件没有匹配 Skill
- **WHEN** incident 不满足任何已注册 Skill 的匹配条件
- **THEN** Harness SHALL 保留既有调查路径或以明确不支持状态结束，不得猜测 Skill 或扩大工具权限

### Requirement: Harness 必须按证据执行位置路由只读工具

Harness SHALL 区分 `requester` 与 `target` 证据步骤。目标步骤 MUST 经过现有 Gateway 身份、能力与授权预检；请求端步骤 MUST 经过现有本地 Tool Runtime。模型只能选择当前 Skill 尚未覆盖且依赖满足的步骤，程序 MUST 核验执行位置、工具名和可信参数。

#### Scenario: 请求端独立探测远端端口
- **WHEN** 目标节点摘要已提供可信私网地址且 incident 提供有效服务端口
- **THEN** Harness SHALL 允许请求端执行一次匹配该地址和端口的 `probe_service_reachability`，并禁止追加或替换参数

#### Scenario: 远端准备失败
- **WHEN** 目标 Gateway 离线、无权限或身份不匹配
- **THEN** Harness SHALL 失败关闭并保留 unknowns，不得用请求端监听、进程或其他本机事实替代目标证据

### Requirement: Harness 必须产生确定终态

正常完成、墙钟超时、远端离线、无权限和用户取消 MUST 分别映射到现有公开终态与停止原因，并保存当时已确认 facts、unknowns、证据引用、预算和工具历史。

#### Scenario: 用户取消调查
- **WHEN** 取消信号在模型或工具步骤前生效
- **THEN** Harness SHALL 传播取消、停止后续调用并以 `cancelled` 保存已有状态

#### Scenario: 墙钟预算耗尽
- **WHEN** 调查在取得部分证据后达到墙钟上限
- **THEN** Harness SHALL 以 `budget_exhausted` 保存部分 facts 和剩余 unknowns，且恢复时不重复已成功步骤
