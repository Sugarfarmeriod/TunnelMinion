## ADDED Requirements

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
