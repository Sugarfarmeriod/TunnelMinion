> **审计状态：部分已实现、部分被替代、部分已拆分。** 受管 Provider、所有权、签名配置、
> direct 联合验证和 last-known-good 已由 `managed-network-provider`、
> `managed-mesh-connectivity` 及归档的 `manage-wireguard-connectivity` 交付。普通 Coordinator
> 兼任 relay 的方案已被替代；专用 relay 由 `build-isolated-packet-relay` 独立承担。Linux
> Provider 也应独立建 change。本文件只保留历史需求以便审计，不应再次 apply 或归档到主规格。

## ADDED Requirements

### Requirement: Agent 自动配置 WireGuard 网络

Agent SHALL 根据协调服务下发的配置，通过 WireGuard Provider 创建和维护本项目拥有的虚拟接口、地址、peer 和路由。Agent MUST NOT 修改或删除不属于本项目的现有 WireGuard 接口和路由。

#### Scenario: 应用有效网络配置

- **WHEN** 已注册 Agent 收到包含本节点地址和 peer 的有效配置
- **THEN** Agent 创建或更新受管 WireGuard 网络，并报告配置应用结果

#### Scenario: 收到无效配置

- **WHEN** Agent 收到缺少必要字段、地址冲突或版本不兼容的网络配置
- **THEN** Agent 拒绝应用该配置、保留最近一次有效配置，并报告可诊断错误

### Requirement: 节点优先使用点对点路径

系统 MUST 在候选节点之间尝试建立直接 WireGuard 路径，并在直连达到可用条件时优先使用该路径传输节点间流量。

#### Scenario: 节点可以直接互通

- **WHEN** 两个在线节点能够通过交换的候选端点建立有效 WireGuard 握手
- **THEN** 两节点之间的活动路径被标记为 `direct`，且业务流量不经过协调节点转发

### Requirement: 直连失败时提供回退路径

> **已被替代并拆分：** 当前主规格要求 relay 是管理员显式启用、独立验证的专用角色，普通
> Coordinator API 不能静默转发。实际 packet 数据面尚未实现，归 `build-isolated-packet-relay`。

协调节点 SHALL 为无法在规定时间内建立直接路径的在线节点提供受管回退路由。Agent MUST 将回退路径状态明确报告为 `relayed`，不得伪装成直接连接。

#### Scenario: NAT 条件阻止直连

- **WHEN** 两个已注册节点在配置的探测窗口内无法建立可用直接路径，但均能连接协调节点
- **THEN** 系统通过协调节点建立回退连通，并将两端路径状态标记为 `relayed`

#### Scenario: 直连从回退状态恢复

- **WHEN** 使用回退路径的节点后来建立稳定直接路径
- **THEN** 系统切换到直接路径并把状态更新为 `direct`，且不要求用户手动重建网络

### Requirement: 网络流量使用 WireGuard 加密

节点在受管虚拟网络上传输的流量 MUST 通过 WireGuard 隧道保护。私钥 MUST 只存在于所属节点，协调服务不得分发任一节点的 WireGuard 私钥。

#### Scenario: 下发 peer 配置

- **WHEN** 协调服务为一个节点生成 peer 配置
- **THEN** 配置只包含远端节点公钥、允许地址和端点信息，不包含远端私钥

### Requirement: 协调服务短时离线时保持已有隧道

Agent MUST 缓存最近一次有效网络配置。协调服务短时不可用时，Agent SHALL 保留仍可工作的受管隧道，并明确报告控制面离线；Agent 不得在单次连接失败后立即拆除网络。

#### Scenario: 协调服务暂时不可达

- **WHEN** 已连通节点失去与协调服务的控制连接，但现有 WireGuard peer 仍然可用
- **THEN** 节点保持现有网络连通，将控制状态标记为离线，并在后台尝试重连

### Requirement: 提供可观察的连接状态

Agent MUST 为每个 peer 提供至少包含连接路径、最近握手时间、可达状态和最近错误的诊断状态。

#### Scenario: 用户查看 peer 状态

- **WHEN** 本地面板请求网络状态
- **THEN** Agent 返回每个 peer 的 `direct`、`relayed`、`connecting` 或 `offline` 状态及可用诊断信息
