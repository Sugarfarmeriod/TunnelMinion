# node-tool-runtime Specification

## Purpose

规定跨平台只读工具的结构化契约、风险等级、注册、参数校验、预算、超时、取消、结果大小、
审计和无模型降级执行边界，并禁止模型通过未知工具或动态代码逃逸固定适配器。

## Requirements
### Requirement: 所有工具具有结构化定义和风险等级

Tool Runtime MUST 为每个工具定义稳定名称、版本、输入 schema、输出 schema、风险等级、支持平台、权限要求、超时和最大结果大小。MVP MUST 只向模型注册 `read-only` 工具。

#### Scenario: 注册有效只读工具

- **WHEN** Runtime 启动并加载符合 schema 的只读工具
- **THEN** 工具进入本节点能力清单，并可在策略允许时暴露给 Agent

#### Scenario: 尝试注册写操作工具

- **WHEN** MVP 配置发现风险等级为 `requires-approval` 或 `forbidden` 的工具
- **THEN** Runtime 不把该工具暴露给模型，并记录策略拒绝原因

### Requirement: 工具参数在执行前验证

Tool Runtime MUST 在调用平台适配器前验证模型提供的参数；未知字段、类型错误、越界值和未注册工具名称 MUST 被拒绝且不得产生系统调用。

#### Scenario: 模型编造工具名称

- **WHEN** 模型请求调用注册表中不存在的工具
- **THEN** Runtime 返回结构化 `tool_not_found` 错误，不执行 Shell、动态导入或相似名称猜测

#### Scenario: 端口参数越界

- **WHEN** 可达性工具收到小于 1 或大于 65535 的端口
- **THEN** Runtime 返回参数校验错误且不发起网络连接

### Requirement: 工具执行受到资源限制

每次工具调用 MUST 具有唯一 `tool_run_id`、超时、取消、并发限制和输出大小限制。达到限制时 Runtime SHALL 终止该调用并返回部分结果可用性与明确错误。

#### Scenario: 平台工具执行超时

- **WHEN** 底层系统查询超过工具超时
- **THEN** Runtime 停止等待、将调用标记为 timeout，并允许 Agent 基于其他证据继续或结束

### Requirement: Runtime 提供基础只读系统工具

Windows 与 macOS Runtime MUST 在平台支持和权限允许时提供 WireGuard 状态、监听端口、进程摘要、Docker 服务和服务可达性工具。权限不足或依赖缺失 MUST 作为结构化降级，而不是使整个 Runtime 崩溃。

#### Scenario: 读取 A 的 WireGuard 状态

- **WHEN** Agent 在 A 调用 WireGuard 状态工具
- **THEN** 工具返回 `HomeMac` 的接口、peer 公钥摘要、允许地址、最近握手和流量统计，且不返回任何私钥

#### Scenario: B 未运行 Docker

- **WHEN** Agent 在 B 调用 Docker 服务工具而 Docker 不可用
- **THEN** 工具返回 `dependency_unavailable`，其他端口、进程和 WireGuard 工具仍可使用

### Requirement: 只读工具不得改变系统状态

MVP 工具 MUST NOT 创建、修改或删除 WireGuard 配置、接口、路由、服务、容器、进程、文件或端口转发。平台适配器测试 MUST 验证调用前后相关系统状态不变。

#### Scenario: 完成一次完整诊断

- **WHEN** Agent 依次调用 WireGuard、端口、进程、Docker 和可达性工具
- **THEN** A 的 `HomeMac` 与 B 的手写配置、接口和服务生命周期保持不变

### Requirement: 每次工具调用可审计

Runtime MUST 记录 run ID、tool run ID、调用节点、执行节点、工具名称/版本、脱敏参数摘要、开始/结束时间、结果状态和错误类型。审计记录 MUST 排除密钥、认证头和工具返回的敏感正文。

#### Scenario: 审计远端工具失败

- **WHEN** A 调用 B 的工具因超时失败
- **THEN** A 与 B 的相关审计记录可以通过关联 ID 对应，并且不泄露节点认证材料
