# coordinator-node-registry Specification

## Purpose
TBD - created by archiving change coordinate-agent-network. Update Purpose after archive.
## Requirements
### Requirement: 管理员可以创建有界的一次性 enrollment token
Coordinator MUST 只允许本机管理员创建绑定 network、有效期和最大使用次数的 enrollment
token，并 MUST 只保存不可逆 token 哈希。

#### Scenario: 创建单次短期 token
- **WHEN** 本机管理员为指定 network 创建一次有效期 10 分钟的 enrollment token
- **THEN** Coordinator 只在创建响应中返回一次完整 token，并持久化哈希、到期时间和剩余次数

#### Scenario: 非管理员远端请求创建 token
- **WHEN** 普通节点凭据或未认证请求调用 enrollment token 管理 API
- **THEN** Coordinator SHALL 拒绝请求且不生成 token

### Requirement: 节点使用本机身份完成幂等注册
Agent MUST 使用本机稳定身份、有效 enrollment token、平台、显示名、Gateway endpoint 和协议
版本注册；Coordinator SHALL 返回稳定 node ID、network ID 和逐节点凭据。

#### Scenario: 新节点首次注册
- **WHEN** 未注册 Agent 使用有效 token 和未占用的本机身份注册
- **THEN** Coordinator 原子消费 token、创建唯一节点并返回只属于该节点的应用凭据

#### Scenario: 相同注册请求重试
- **WHEN** 网络超时后同一设备以相同幂等键重试已成功的注册
- **THEN** Coordinator SHALL 返回同一 node ID，不创建重复节点或再次消耗 token

### Requirement: enrollment token 的无效使用必须安全失败
Coordinator MUST 拒绝过期、已消费、已撤销、network 不匹配或超过速率限制的 token，且不得
泄露 token 是否曾属于其他 network。

#### Scenario: 重放已消费 token
- **WHEN** 第二个设备重放已经成功使用的一次性 token
- **THEN** Coordinator SHALL 返回稳定的认证失败，不创建节点或凭据

#### Scenario: token 已过期
- **WHEN** Agent 在 token 到期后提交注册
- **THEN** Coordinator SHALL 拒绝注册且不改变节点目录

### Requirement: 节点 refresh 凭据必须隔离并可轮换
Coordinator MUST 为每个节点签发独立高熵 refresh 凭据并只保存验证所需哈希；Agent MUST 将完整凭据
保存到操作系统秘密存储，不得写入普通配置、日志或模型上下文。

#### Scenario: Agent 重启后重连
- **WHEN** 已注册 Agent 从本机秘密存储读取凭据并重新连接
- **THEN** Coordinator SHALL 恢复原 node ID，且不要求重新 enrollment

#### Scenario: 节点凭据轮换
- **WHEN** 本机管理员为未撤销节点完成凭据轮换
- **THEN** 新凭据生效、旧凭据失效，并记录不含凭据正文的审计事件

### Requirement: Coordinator 签发有界短期访问 assertion
已认证且未撤销节点 SHALL 能使用 refresh 凭据获取标准格式的签名 access assertion；assertion
MUST 绑定 network、node、audience、协议主版本、唯一 ID 和短期有效期。

#### Scenario: 为 Tool Gateway 获取 assertion
- **WHEN** 在线节点请求 audience 为 `tool-gateway` 的 access assertion
- **THEN** Coordinator SHALL 返回可由已固定验证公钥离线验证的短期 assertion

#### Scenario: assertion audience 不匹配
- **WHEN** 客户端把只允许访问 Coordinator 的 assertion 提交给 Tool Gateway
- **THEN** Gateway SHALL 拒绝认证且不执行工具

### Requirement: Coordinator 签名密钥必须受保护并可轮换
Coordinator MUST 将签名私钥保存在秘密存储，发布带 key ID 的验证公钥集合，并使用明确的
重叠窗口轮换；Agent 和 Gateway MUST 固定管理员信任的公钥指纹。

#### Scenario: 响应包含未知签名 key ID
- **WHEN** Gateway 收到由未固定 key ID 签名的 assertion
- **THEN** Gateway SHALL 拒绝请求，不得从 assertion 自带地址自动下载并信任公钥

### Requirement: Coordinator 确定性维护节点状态
Agent SHALL 周期性发送认证心跳；Coordinator MUST 根据服务器接收时间、配置阈值、撤销状态和
协议兼容性确定 `online`、`stale`、`offline`、`revoked` 或 `incompatible`。

#### Scenario: 节点停止心跳
- **WHEN** 节点超过 stale 和 offline 阈值未成功通信
- **THEN** Coordinator SHALL 依次将其标记为 stale 和 offline，并使目录不再表示其能力可用

#### Scenario: Agent 时钟明显错误
- **WHEN** 心跳携带的本机时间偏离 Coordinator 时间
- **THEN** 在线状态仍 SHALL 使用服务器接收时间，Agent 时间只作为脱敏诊断字段

### Requirement: 管理员可以立即撤销节点
本机管理员 MUST 能撤销指定节点；撤销 SHALL 立即拒绝该节点 refresh 凭据、新 assertion 签发、
心跳、快照更新和目录查询，并保留不含秘密的审计关系。

#### Scenario: 撤销在线节点
- **WHEN** 管理员撤销当前在线节点
- **THEN** Coordinator SHALL 将节点标记为 revoked、发布撤销修订并拒绝其下一次认证请求

#### Scenario: 被撤销节点尝试重新 enrollment
- **WHEN** 原设备使用新的 enrollment token 但仍提交已撤销身份
- **THEN** Coordinator SHALL 拒绝静默恢复，必须经过显式管理员恢复或新身份流程

### Requirement: 协议版本不兼容时不得进入正常同步
注册与认证请求 MUST 携带协议版本；Coordinator MUST 拒绝不支持的主版本，并 MAY 接受受支持
主版本内的向后兼容次版本。

#### Scenario: Agent 主版本过新
- **WHEN** Agent 使用 Coordinator 不支持的协议主版本注册或发送心跳
- **THEN** Coordinator SHALL 返回 `version_incompatible`，且不更新在线时间或目录

### Requirement: network 边界必须硬隔离
Coordinator MUST 按 network 隔离 token、节点、凭据、目录和修订；节点凭据 SHALL 只能读取
所属 network 的有权摘要并更新自身状态。

#### Scenario: 节点请求其他 network
- **WHEN** 已认证节点在查询或快照请求中指定不同 network ID
- **THEN** Coordinator SHALL 返回 `forbidden`，响应不得包含另一 network 是否存在

### Requirement: 注册与认证日志不得泄露秘密
Coordinator SHALL 记录有界 node/network、动作、结果、错误码和时间；普通日志与审计导出
MUST NOT 包含完整 token、节点凭据、认证头或可重放材料。

#### Scenario: 注册失败导出审计
- **WHEN** 管理员导出 token 重放和版本不兼容事件
- **THEN** 导出 SHALL 支持关联事件但不包含任何完整认证材料

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

