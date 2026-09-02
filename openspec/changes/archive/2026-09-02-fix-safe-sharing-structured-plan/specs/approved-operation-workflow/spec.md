## ADDED Requirements

### Requirement: Provider 候选计划说明必须经过本地边界校验
系统 SHALL 对 OpenAI-compatible Provider 返回的候选计划说明执行本地 schema 校验，并且只允许模型提供预期变化、风险、验证方法和回滚方法；节点、端口、操作等级、工具、证据和授权状态 MUST 由服务端固定。

#### Scenario: Provider 返回有效的候选计划说明
- **WHEN** Provider 返回满足本地 schema 的四个说明字段
- **THEN** 系统 SHALL 将说明与服务端固定字段组合为候选计划，且不执行或批准该计划

#### Scenario: Prompt injection 尝试覆盖固定字段
- **WHEN** 用户文本要求模型改变节点、端口、操作等级、工具、证据或授权状态
- **THEN** 系统 SHALL 忽略这些模型影响并继续使用服务端固定字段，无法得到合法说明时则拒绝创建候选计划
