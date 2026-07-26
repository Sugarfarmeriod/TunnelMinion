## ADDED Requirements

### Requirement: 节点可以注册最小受管网络身份
已认证节点 SHALL 能为指定受管 network 注册 WireGuard 公钥、Provider 类型和有界候选 endpoint
摘要；Coordinator MUST NOT 接收私钥、预共享密钥、完整平台配置或用户路由表。

#### Scenario: B 注册受管公钥
- **WHEN** B 使用有效 refresh 凭据提交新公钥和候选摘要
- **THEN** Coordinator SHALL 绑定到 B 的稳定 node ID 并生成 network 修订

#### Scenario: 请求含私钥字段
- **WHEN** 受管网络注册包含 schema 未声明的秘密或配置正文
- **THEN** Coordinator SHALL 拒绝整个请求并记录脱敏 schema 错误

### Requirement: 地址租约和网络公钥必须具有生命周期
Coordinator SHALL 记录地址租约、公钥状态、配置父修订、创建/轮换/撤销时间和最小审计关系；
节点撤销 SHALL 阻止新配置并释放策略允许释放的未激活租约，但不得远程删除节点本机资源。

#### Scenario: 轮换节点网络公钥
- **WHEN** 本机已批准的 key rotation 注册新公钥
- **THEN** Coordinator SHALL 创建新配置修订并保留旧 key 的有界切换状态，不能静默覆盖 active key

#### Scenario: 节点被撤销
- **WHEN** 管理员撤销已加入受管 network 的节点
- **THEN** Coordinator SHALL 停止发布包含该节点的新 active 配置，并要求其余节点收敛撤销修订

### Requirement: relay 角色必须由管理员显式注册
Coordinator MUST 区分普通节点、relay-capable 与 active relay，并 SHALL 只为本机管理员启用且
通过前置能力验证的节点发布 relay 候选。

#### Scenario: 普通节点自报 relay
- **WHEN** 普通 Agent 仅在状态请求中声称具备 relay 能力
- **THEN** Coordinator SHALL 不把它升级为 relay 角色

#### Scenario: 管理员撤销 relay
- **WHEN** active relay 的管理员授权被撤销
- **THEN** Coordinator SHALL 生成路径修订，并且新连接不得继续选择该 relay
