## ADDED Requirements

### Requirement: NetworkProvider 必须区分只读观察与受管模式
系统 MUST 将用户已有网络资源视为 `observed-user`，只有具备有效 TunnelMinion 所有权记录的
独立资源才能进入 `managed-owned` 模式；模式不得由模型、接口名称或配置内容自行推断。

#### Scenario: 观察现有 HomeMac
- **WHEN** Windows Provider 发现用户已有的 `HomeMac` 接口
- **THEN** Provider SHALL 返回脱敏状态并拒绝为其生成 apply、rollback 或 delete 计划

#### Scenario: 名称看似属于 TunnelMinion 但没有账本
- **WHEN** 系统发现带受管前缀但没有本地所有权记录的接口
- **THEN** Provider SHALL 将其标记为 ownership unknown，不得接管或删除

### Requirement: Provider 计划必须确定、有界且可预览
Provider SHALL 根据结构化 desired config 和实时 observed state 生成不含秘密的差异计划；计划
MUST 固定 network/node、接口、地址、host routes、peer 公钥、endpoint、步骤上限、父配置修订和
计划哈希，并 MUST 拒绝默认路由、未批准子网、未知字段和动态命令。

#### Scenario: 计划创建独立测试接口
- **WHEN** desired config 使用不冲突 host address、明确 peer 和允许的独立接口名称
- **THEN** Provider SHALL 返回可供本机批准的逐步 diff，且生成计划期间不改变系统

#### Scenario: 配置请求默认路由
- **WHEN** desired config 包含 `0.0.0.0/0`、`::/0` 或批准范围外的子网
- **THEN** Provider SHALL 在调用平台写接口前返回 `route_not_allowed`

### Requirement: WireGuard 私钥必须只属于生成节点
Provider MUST 在所属节点生成 WireGuard 私钥，并只写入操作系统秘密存储或平台运行所必需的
ACL 受限文件；普通配置、SQLite、Coordinator、日志、导出、模型上下文和操作 diff MUST NOT
包含私钥或预共享密钥正文。

#### Scenario: Coordinator 请求节点网络元数据
- **WHEN** Agent 构建受管网络注册或状态请求
- **THEN** 请求 SHALL 只包含公钥、秘密引用存在状态和脱敏配置摘要

#### Scenario: 删除受管网络
- **WHEN** 所有权验证后的受管网络完成删除
- **THEN** Provider SHALL 删除对应秘密引用，并证明审计/导出中没有残留可重放密钥

### Requirement: 所有受管资源必须具有双重所有权证据
系统 SHALL 保存 network/node、Provider、接口稳定 ID、创建 nonce、公钥、父配置、期望配置哈希
和系统资源指纹；任何修改、回滚或删除 MUST 同时匹配本地账本和实时系统指纹。

#### Scenario: 资源仍属于当前受管配置
- **WHEN** 账本、接口稳定 ID、公钥和实时指纹均匹配
- **THEN** Provider MAY 在有效 L3 授权内应用精确计划

#### Scenario: 用户手工替换了同名接口
- **WHEN** 接口名称相同但稳定 ID、公钥或系统指纹与账本不一致
- **THEN** Provider SHALL 进入 `ownership_conflict`，不修改或删除该接口

### Requirement: Provider 应用必须幂等并经过独立验证
Provider MUST 按配置 revision 和幂等键串行应用固定步骤，记录逐步回执；成功只能由重新读取
接口、地址、peer、route、握手和目标探测的 `verify` 确认，不能由命令退出码单独确认。

#### Scenario: 相同 revision 重试
- **WHEN** 响应丢失后 Agent 使用相同幂等键重新应用已经验证的 revision
- **THEN** Provider SHALL 返回原验证回执且不重复创建接口、地址或 route

#### Scenario: 命令成功但 route 缺失
- **WHEN** 平台命令返回成功但重新读取未发现期望 host route
- **THEN** Provider SHALL 把应用标记为验证失败并进入回滚

### Requirement: 部分失败必须回滚到父配置
每个写步骤 MUST 具有已验证前置条件和可关联的反向步骤；任一步骤或执行后验证失败时 Provider
SHALL 按回执逆序恢复父 revision，回滚同样 MUST 重新读取验证。

#### Scenario: 第二个 peer 应用失败
- **WHEN** 接口和地址已创建但 peer 配置失败
- **THEN** Provider SHALL 只回滚本次已确认步骤，并证明父配置或无配置状态恢复

#### Scenario: 回滚时所有权不再匹配
- **WHEN** 回滚前检测到受管资源被外部进程替换
- **THEN** Provider SHALL 停止自动清理、标记 `manual_intervention` 并保留脱敏恢复建议

### Requirement: Windows 与 macOS Provider 必须遵守同一契约
Windows 和 macOS Provider SHALL 使用固定官方工具/服务适配器实现同一结构化错误、计划、
回执和状态模型；依赖缺失或权限不足 MUST 只使 managed 能力降级，不得阻止只读工具、资源页、
static peer、租约恢复或本地紧急停止。

#### Scenario: macOS 当前账户无网络管理权限
- **WHEN** macOS Provider 预检发现无法创建独立接口
- **THEN** 系统 SHALL 返回 `permission_denied` 且不尝试 sudo prompt 或修改 B 手写配置

#### Scenario: Windows tunnel service 不可用
- **WHEN** Windows Provider 找不到受支持的 WireGuard service 接口
- **THEN** 系统 SHALL 显示 managed Provider 不可用，`HomeMac` 只读观察继续工作

### Requirement: 恢复与卸载只能清理可证明自有的资源
Agent 重启或崩溃后 SHALL 对未完成回执执行恢复检查；卸载 SHALL 删除秘密、账本和实时指纹均
匹配的受管资源，并 MUST 保留所有 `observed-user` 或 ownership conflict 资源。

#### Scenario: 应用中途 Agent 崩溃
- **WHEN** 重启发现配置处于 applying 且存在逐步回执
- **THEN** 恢复器 SHALL 在模型和 Coordinator 均不可用时验证现状并完成父配置回滚或明确升级

#### Scenario: 卸载时存在 HomeMac 和受管测试接口
- **WHEN** 用户执行完整卸载
- **THEN** 系统 SHALL 只删除指纹匹配的受管测试接口，`HomeMac`、B 手写配置和用户路由保持不变
