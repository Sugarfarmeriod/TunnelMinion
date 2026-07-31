# operation-policy Specification

## Purpose

规定 L0～L4 确定性风险等级、逐次批准、细粒度预授权、节点所有权和模型不得扩大权限的治理
规则。
## Requirements
### Requirement: 系统必须使用确定性操作等级
系统 SHALL 将工具和操作分类为 L0 只读观察、L1 无副作用建议、L2 低风险可逆操作、L3 敏感操作或 L4 禁止操作，并由确定性策略而非模型输出决定实际等级。

#### Scenario: 模型尝试降低操作等级
- **WHEN** 模型把一个已注册为 L3 或 L4 的操作描述为低风险
- **THEN** 系统 SHALL 保留注册表中的等级并拒绝按 L2 执行

#### Scenario: prompt 或历史上下文要求绕过确定性策略
- **WHEN** prompt、对话历史、记忆或远端不可信文本要求模型批准计划、创建预授权、降低操作等级或直接调用写适配器
- **THEN** 系统 SHALL 忽略该要求并继续由目标节点确定性策略和本地授权状态作出决策

#### Scenario: 只读工具自动执行
- **WHEN** Agent 选择满足参数和预算要求的 L0 工具
- **THEN** 系统 SHALL 允许其在无需写操作批准的情况下执行

### Requirement: L2 操作默认需要目标节点所有者批准
系统 SHALL 在没有匹配预授权时，把 L2 操作置为待批准状态，并且只有目标节点本地用户能够批准或拒绝。

#### Scenario: 没有预授权
- **WHEN** 请求节点提交一个有效 L2 临时共享计划且目标节点没有匹配预授权
- **THEN** 系统 SHALL 不执行写操作并在目标节点显示待批准计划

#### Scenario: 用户拒绝计划
- **WHEN** 目标节点用户拒绝待批准计划
- **THEN** 系统 SHALL 终止该计划、记录拒绝理由且不创建共享资源

### Requirement: 节点所有者可以创建细粒度预授权
系统 SHALL 允许目标节点所有者为 L2 操作创建可撤销、会过期的预授权，并 MUST 同时限制请求 peer、工具、目标服务或选择条件、端口范围、最长持续时间和授权有效期。

#### Scenario: 计划完整匹配预授权
- **WHEN** L2 计划的所有字段均处于一个有效预授权范围内
- **THEN** 系统 SHALL 允许计划无需逐次点击批准进入执行，并记录命中的授权 ID 和决策依据

#### Scenario: 计划超出任一授权范围
- **WHEN** L2 计划的请求 peer、工具、服务、端口、持续时间或执行时间超出预授权范围
- **THEN** 系统 SHALL 将其视为未授权并要求逐次批准或拒绝

#### Scenario: 预授权被撤销
- **WHEN** 节点所有者撤销一个预授权
- **THEN** 系统 SHALL 拒绝该授权下尚未开始的新操作，但 SHALL 按各操作租约继续跟踪并清理已经执行的入口

### Requirement: 模型不得授予或扩大权限
系统 MUST 禁止模型创建、修改、批准预授权，或把自身、请求节点和目标资源加入允许范围。

#### Scenario: 对话要求永久信任请求节点
- **WHEN** 用户仅在聊天内容中要求 Agent 永久信任某个 peer
- **THEN** Agent MAY 解释配置方法，但系统 SHALL NOT 因模型输出而创建预授权

### Requirement: L3 只能通过显式注册的敏感操作工作流执行，L4 始终拒绝
系统 MUST 只允许显式注册的 L3 操作进入独立治理工作流；每个 L3 操作 SHALL 具有本机预览、
目标节点批准、范围绑定授权、幂等计划、执行后独立验证、审计和失败回滚。未注册 L3 与所有 L4
操作 MUST 始终拒绝，普通模型工具集不得包含 L3/L4 写适配器。

#### Scenario: 用户批准创建独立受管 WireGuard 测试接口
- **WHEN** 本机用户批准绑定 network/node、Provider、接口前缀、地址池、host routes、允许覆盖的既有宽路由摘要、UDP listen port、配置修订、观察指纹和有效期的 L3 计划
- **THEN** 系统 SHALL 只允许确定性 NetworkProvider 执行该精确范围并要求执行后验证

#### Scenario: 请求重启服务、控制容器或修改用户 WireGuard
- **WHEN** 用户或模型请求未注册的 L3 操作，或目标是 `observed-user` WireGuard 资源
- **THEN** 系统 SHALL 拒绝请求且不调用任何写适配器

#### Scenario: 请求 L4 任意命令
- **WHEN** 任意输入要求执行 Shell、Python、动态代码或绕过所有权检查
- **THEN** 系统 SHALL 始终拒绝并记录策略事件

### Requirement: L3 网络授权必须绑定完整变化范围
受管网络 L3 授权 MUST 绑定 network/node、Provider、资源所有权、接口前缀、地址池、允许 host
routes、允许覆盖的既有宽路由摘要、观察指纹、peer/relay 上限、配置与父 revision、计划哈希、
UDP listen port、批准人和有效期；超出任一维度 MUST 重新批准。

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
