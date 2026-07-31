> **审计状态：已实现并被更精确的主规格取代。** token、幂等注册、逐节点 refresh 凭据、短期
> assertion、心跳、撤销、network 隔离和版本行为由 `coordinator-node-registry` 与
> `coordinator-client-sync` 规定。旧文中的“设备密钥直接换取虚拟地址和网络配置”不再是当前
> 身份边界：WireGuard 公钥、地址租约和签名 desired config 具有独立生命周期。本文件只保留
> 历史需求以便审计，不应再次 apply 或归档到主规格。

## ADDED Requirements

### Requirement: 节点可以加入协调网络

Agent MUST 接受协调服务地址和有效的短期 enrollment token，并使用本机生成的设备身份完成注册。成功注册后，协调服务 SHALL 返回稳定节点 ID、虚拟地址和建立网络所需的配置。

#### Scenario: 使用有效 token 首次注册

- **WHEN** 未注册 Agent 使用可用的协调地址和有效 enrollment token 发起注册
- **THEN** 协调服务创建唯一节点身份并返回稳定节点 ID、虚拟地址和初始配置

#### Scenario: 拒绝无效或过期 token

- **WHEN** Agent 使用无效、过期或已撤销的 enrollment token 发起注册
- **THEN** 协调服务拒绝注册，且不分配节点身份或虚拟地址

### Requirement: 节点身份在本机安全持久化

Agent MUST 在本机生成设备密钥，并使用操作系统安全存储或仅当前系统账户可读的受限文件保存长期凭据。私钥 MUST NOT 发送给协调服务或写入普通日志。

#### Scenario: 注册完成后重启 Agent

- **WHEN** 已注册 Agent 在同一设备上重启并重新连接协调服务
- **THEN** Agent 使用已有设备身份恢复原节点 ID 和虚拟地址，而不是创建重复节点

#### Scenario: 输出诊断日志

- **WHEN** Agent 输出注册或重连诊断信息
- **THEN** 日志不包含设备私钥、完整 token 或可重放认证凭据

### Requirement: 协调服务维护节点在线状态

Agent SHALL 周期性向协调服务发送带协议版本的心跳或状态更新，协调服务 MUST 根据最后成功通信时间将节点标记为在线、离线或不兼容。

#### Scenario: 节点停止心跳

- **WHEN** 协调服务在配置的超时时间内未收到节点心跳
- **THEN** 该节点被标记为离线，其他节点能够观察到该状态

#### Scenario: 协议版本不兼容

- **WHEN** Agent 使用协调服务不支持的协议版本连接
- **THEN** 协调服务拒绝进入正常会话并返回明确的不兼容错误

### Requirement: 管理员可以撤销节点

协调服务 MUST 允许管理员撤销单个节点身份。被撤销节点 MUST 无法继续获取配置或更新网络目录，且其他节点 SHALL 在下一次配置收敛时移除其 peer 信息。

#### Scenario: 撤销已在线节点

- **WHEN** 管理员撤销一个已注册节点
- **THEN** 该节点的控制会话失效，后续认证被拒绝，并从其他节点的有效 peer 配置中移除

### Requirement: 三端具备一致注册行为

Windows、macOS、Linux Agent MUST 遵循相同的注册、重连、错误和撤销语义；平台存储方式可以不同，但不得改变用户可观察结果。

#### Scenario: 在支持的平台注册节点

- **WHEN** 用户分别在 Windows、macOS 或 Linux 上使用相同类型的有效注册信息
- **THEN** 每个平台都能生成独立身份、完成注册并在重启后恢复该身份
