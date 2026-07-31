# cross-node-diagnostics Specification

## Purpose

规定经现有 WireGuard 私网认证调用远端只读工具、分阶段发现能力、组合服务证据和安全处理
节点离线与来源降级的行为。
## Requirements
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

### Requirement: 跨节点目标必须解析为已验证目录条目
当启用 Coordinator 时，Runtime MUST 按稳定 node ID 解析所属 network 中的 Gateway endpoint、
节点状态、协议版本和能力摘要；不得让模型直接提供未验证 endpoint 或认证材料。

#### Scenario: 按节点 ID 诊断在线节点
- **WHEN** 用户要求诊断目录中 fresh 且已授权的 B
- **THEN** Runtime SHALL 解析 B 的当前 Gateway endpoint，并在模型外附加本机保存的逐节点凭据

#### Scenario: 模型提供任意远端地址
- **WHEN** 模型工具参数包含不属于已验证目录或显式静态 peer 的 endpoint
- **THEN** Runtime SHALL 拒绝调用，且不得把地址加入 peer 配置

### Requirement: 目录发现必须经过目标 Gateway 直连复核
目录能力只用于预筛选；Runtime MUST 在首次调用或目录修订变化后从目标 Gateway 获取节点摘要
和能力，并以更新的直连证据处理冲突。

#### Scenario: 目录声称工具可用但目标已移除
- **WHEN** Coordinator 目录包含 Docker 能力但 B 的直连能力清单已不包含该工具
- **THEN** A SHALL 不向模型暴露该远端工具，记录目录陈旧并触发后续同步

### Requirement: Coordinator-managed 直连必须使用短期签名身份
Runtime MUST 为 Coordinator-managed peer 使用绑定 network、调用 node、Gateway audience 和
短期有效期的签名 assertion；目标 Gateway MUST 离线验签并继续执行本地授权与工具策略。

#### Scenario: 使用有效 assertion 调用 B
- **WHEN** A 使用有效短期 assertion 请求 B 的能力摘要
- **THEN** B SHALL 验证签名、audience、network、node、期限和本地授权状态后返回允许摘要

#### Scenario: assertion 已过期或节点已撤销
- **WHEN** A 提交过期 assertion 或 B 的授权缓存已标记 A revoked
- **THEN** B SHALL 拒绝请求、不执行工具并记录脱敏认证错误

### Requirement: Coordinator 故障时远端解析必须安全降级
Coordinator 不可用时，Runtime MAY 使用显式静态 peer，或在 endpoint TTL 内使用已完成直连
验证的缓存目录条目；过期、撤销、未验证或版本不兼容条目 MUST NOT 自动调用。

#### Scenario: Coordinator 离线但静态 B 仍可用
- **WHEN** A 无法刷新目录且本机仍有明确配置并通过策略校验的 B static peer
- **THEN** A SHALL 继续按原 Gateway 流程诊断 B，并标记 Coordinator 目录不可用

#### Scenario: 只有过期目录 endpoint
- **WHEN** 目标没有 static peer 且缓存 endpoint 已超过 TTL
- **THEN** Runtime SHALL 返回目录陈旧或节点不可解析，不尝试网络调用

### Requirement: 远端 endpoint 选择必须表达受管路径状态
启用受管网络时，Runtime SHALL 在模型外按 verified managed path、fresh static peer 和过期/失败
状态选择 endpoint；`direct`、`relayed` 与 static MUST 在证据和审计中区分，不能把控制面声明
当作可达事实。

#### Scenario: 受管 direct 路径已经验证
- **WHEN** B 的 managed endpoint、配置 revision 和路径验证均 fresh
- **THEN** A SHALL 优先使用该 endpoint，仍执行 Gateway 身份和实时能力复核

#### Scenario: managed 路径 degraded 但 static peer 可用
- **WHEN** managed direct/relay 未验证且显式 static B 仍通过原策略
- **THEN** Runtime SHALL 使用 static peer 并明确记录 managed 降级，不自动改写目录

### Requirement: 网络 L3 写入不得通过远端工具调用实现
跨节点 Tool/Operation Gateway MUST NOT 因 managed network 启用而暴露 WireGuard 写工具；每个
节点的 NetworkProvider 只能消费其本机治理工作流验证的签名配置和授权。

#### Scenario: A 模型要求 B 立即改 peer
- **WHEN** A 通过对话或远端工具请求 B 修改 WireGuard peer
- **THEN** B Gateway SHALL 拒绝写调用；B 只有在自身 L3 policy 满足时才能本地执行配置修订
