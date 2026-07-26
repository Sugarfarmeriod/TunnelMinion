## ADDED Requirements

### Requirement: 节点通过现有 WireGuard 网络提供远端工具网关

A 与 B 的 Tool Gateway MUST 只绑定明确配置的 WireGuard 地址，并验证调用节点身份。Gateway MUST NOT 绑定公网或物理局域网通配地址。

#### Scenario: A 通过 WireGuard 调用 B

- **WHEN** A 使用已配置的 B WireGuard 地址和有效节点身份请求能力清单
- **THEN** B 返回允许暴露给 A 的只读工具摘要

#### Scenario: 未认证请求访问 B

- **WHEN** 请求缺少有效节点身份或来自非允许节点
- **THEN** B 拒绝请求、不执行工具，并写入不含秘密的安全审计事件

### Requirement: Agent 分阶段发现远端能力

Runtime SHALL 先获取节点摘要与能力，再根据目标节点、平台、权限和当前任务动态提供远端工具。离线、不支持或未授权工具 MUST NOT 进入当前模型工具集合。

#### Scenario: B 没有 Docker 能力

- **WHEN** B 的能力清单表明 Docker 工具不可用
- **THEN** A 的 Agent 不向模型暴露 B 的 Docker 调用，并可选择端口/进程工具作为替代证据

### Requirement: 远端调用具有超时、取消和结果预算

跨节点工具请求 MUST 传播 run ID、tool run ID、超时和取消状态，并限制响应大小。网络断开时调用 SHALL 失败为明确的远端不可达错误，不得无限等待。

#### Scenario: B 在执行期间离线

- **WHEN** A 已发起远端工具调用而 B 连接中断
- **THEN** A 在超时内收到 `node_unreachable` 或 `remote_timeout`，Agent 可据此说明诊断不完整

### Requirement: Agent 可以发现远端节点服务

Agent MUST 能组合远端监听端口、进程和可选 Docker 工具结果，形成带来源和时间的服务摘要，并区分远端可访问与仅监听环回的服务。

#### Scenario: B 运行仅监听本机的 PDF 服务

- **WHEN** B 的工具结果显示 PDF 容器对应服务只监听 `127.0.0.1:8080`
- **THEN** A 的 Agent 将其识别为 B 上的 `local-only` 服务，并引用 B 的端口与容器证据

### Requirement: Agent 可以诊断跨节点服务不可达

对于“远端服务为何打不开”的问题，Agent SHALL 至少考虑目标节点在线状态、WireGuard peer 状态、监听地址、端口/容器映射和从请求节点执行的可达性探测。缺少关键证据时 MUST 明确说明。

#### Scenario: 监听地址导致不可达

- **WHEN** B 在线、WireGuard peer 可达、服务只监听环回且 A 的端口探测失败
- **THEN** Agent 判断当前主要原因是监听范围，并建议后续可选方案，但不声称已经修改 B

#### Scenario: B 整体离线

- **WHEN** A 无法通过 WireGuard 到达 B 且远端网关也不可用
- **THEN** Agent 优先报告节点/隧道不可达，不虚构 B 当前端口或容器状态

### Requirement: 两端均可独立使用本地 Agent

A 与 B MUST 各自能够打开本地面板、配置自己的模型、查询本机状态并在授权范围内查询另一节点。一个节点的模型不可用 MUST NOT 阻止另一节点的本地 Agent 工作。

#### Scenario: B 未配置模型但工具网关在线

- **WHEN** B 没有模型配置而 A 的模型可用
- **THEN** A 仍可调用 B 的只读工具完成跨节点诊断，B 本地仅缺少 AI 对话能力

### Requirement: MVP 禁止跨节点写操作

远端 Gateway MUST 拒绝任何修改网络、发布端口、重启服务、控制容器或执行任意命令的请求，即使模型或已认证节点提出该请求。

#### Scenario: A 请求 B 临时开放端口

- **WHEN** MVP 中 A 的 Agent 尝试请求 B 发布一个本地服务
- **THEN** B 返回 `operation_not_supported` 或策略拒绝，且系统状态保持不变
