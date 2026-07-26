## ADDED Requirements

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
