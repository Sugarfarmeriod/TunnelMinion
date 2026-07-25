# operation-policy Specification

## Purpose
TBD - created by archiving change approve-and-share-local-service. Update Purpose after archive.
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

### Requirement: L3 和 L4 保持在本 change 范围外
系统 MUST 不注册本 change 的 L3 执行工具，并 SHALL 始终拒绝 L4 操作。

#### Scenario: 请求重启服务或修改 WireGuard
- **WHEN** 用户要求 Agent 重启服务、控制容器或修改 WireGuard 配置
- **THEN** 系统 SHALL 不把该请求转换为临时共享操作，也 SHALL 不执行任何写工具

