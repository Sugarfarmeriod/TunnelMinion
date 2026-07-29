## MODIFIED Requirements

### Requirement: L3 只能通过显式注册的敏感操作工作流执行，L4 始终拒绝
系统 MUST 只允许显式注册的 L3 操作进入独立治理工作流；每个 L3 操作 SHALL 具有本机预览、
目标节点批准、范围绑定授权、幂等计划、执行后独立验证、审计和失败回滚。未注册 L3 与所有 L4
操作 MUST 始终拒绝，普通模型工具集不得包含 L3/L4 写适配器。

#### Scenario: 用户批准创建独立受管 WireGuard 测试接口
- **WHEN** 本机用户批准绑定 network/node、Provider、接口前缀、地址池、host routes、允许覆盖的既有宽路由摘要、配置修订、观察指纹和有效期的 L3 计划
- **THEN** 系统 SHALL 只允许确定性 NetworkProvider 执行该精确范围并要求执行后验证

#### Scenario: 请求重启服务、控制容器或修改用户 WireGuard
- **WHEN** 用户或模型请求未注册的 L3 操作，或目标是 `observed-user` WireGuard 资源
- **THEN** 系统 SHALL 拒绝请求且不调用任何写适配器

#### Scenario: 请求 L4 任意命令
- **WHEN** 任意输入要求执行 Shell、Python、动态代码或绕过所有权检查
- **THEN** 系统 SHALL 始终拒绝并记录策略事件

## ADDED Requirements

### Requirement: L3 网络授权必须绑定完整变化范围
受管网络 L3 授权 MUST 绑定 network/node、Provider、资源所有权、接口前缀、地址池、允许 host
routes、允许覆盖的既有宽路由摘要、观察指纹、peer/relay 上限、配置与父 revision、计划哈希、
批准人和有效期；超出任一维度 MUST 重新批准。

#### Scenario: 新 revision 只修复同一 peer
- **WHEN** 幂等修复没有扩大地址、route、peer、relay 或资源范围且授权仍有效
- **THEN** 系统 MAY 自动执行并记录命中的 L3 policy

#### Scenario: Coordinator 增加一个 route
- **WHEN** desired config 包含批准范围外的新 host route
- **THEN** 系统 SHALL 停在 `awaiting_authorization`，不得因配置已签名而自动执行

#### Scenario: 签名配置声明 Mihomo 宽路由例外但本机未批准
- **WHEN** desired config 包含允许覆盖的既有宽路由摘要，而目标节点本机授权未绑定同一 `/32`、宽路由和观察指纹
- **THEN** 系统 SHALL 停在 `awaiting_authorization`，不得调用 Provider 写接口

### Requirement: 本机紧急停止不依赖模型或 Coordinator
节点所有者 SHALL 能在控制面和模型均离线时停止指纹匹配的受管网络资源；紧急停止 MUST 保留
恢复回执，且不得作用于用户资源或 ownership conflict。

#### Scenario: Coordinator 离线时停止测试隧道
- **WHEN** 本机用户确认紧急停止且所有权实时匹配
- **THEN** Provider SHALL 停止受管接口、验证结果并保存可恢复状态
