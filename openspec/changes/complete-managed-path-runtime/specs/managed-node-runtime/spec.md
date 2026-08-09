## MODIFIED Requirements

### Requirement: managed config 必须进入既有治理而不是直接写系统

运行时 SHALL 拉取并验证属于本机的签名 desired config，将合法下一 revision 保存为 pending，并由每个 network/node 的单一 managed path lifecycle 只通过现有本机持久化 L3 policy/authorization 和 Provider observe/plan/apply/verify/rollback/recover 边界执行。授权 MUST 与 network、node、revision、Provider、资源范围、计划摘要/观察指纹和有效期精确匹配，并在 Provider apply 前重新读取。模型、对话、记忆、服务快照、Coordinator、页面和普通启动 MUST NOT 创建、扩大或代替授权，也不得直接调用网络写入。

#### Scenario: 收到合法配置但没有本机授权

- **WHEN** 签名 desired config 通过目标、父 revision、指纹、协议和预算校验，但没有精确有效的本机 L3 授权
- **THEN** 运行时保存 pending 并显示 `awaiting-authorization`，不调用 Provider apply、不创建授权且不改变网络状态

#### Scenario: Provider 验证失败

- **WHEN** 已授权配置的 apply 返回回执但独立 verify 失败
- **THEN** 既有治理执行回滚或进入人工干预，运行时不得上报 verified 或覆盖 last-known-good

#### Scenario: 授权与计划不匹配

- **WHEN** 本机授权的 revision、Provider、资源范围、计划摘要、观察指纹或有效期与待执行计划不一致
- **THEN** 运行时在任何 Provider 写入前 fail closed，保留 pending 并发布不含计划正文的稳定错误

### Requirement: 本地资源视图必须分域、脱敏且可解释

环回资源 API/页面 SHALL 分别显示 managed 配置/enrollment、目录同步、服务观察、managed config、授权、路径与 last-known-good 状态，包括真实 selection、证据各维度、来源、新鲜度、修订、最后成功、退避、计数和稳定错误。Windows/macOS 常规入口 MUST 从共享 lifecycle 的持久化状态读取这些字段；未装配、待授权、过期和探测失败 MUST 分别表达，不得用占位值、缓存或旧证据误报当前可用。响应 MUST NOT 包含完整 token、refresh、assertion、签名、私钥、完整 endpoint、配置正文或用户路由。

#### Scenario: 本地可用但控制面离线

- **WHEN** Coordinator 不可达而本地工具与已有 static/direct 路径仍可用
- **THEN** 页面明确区分控制面离线、path evidence 新鲜度和仍可用的数据面，不把整个节点笼统显示为 offline

#### Scenario: 读取资源 API

- **WHEN** 用户请求 managed node 状态并导出诊断
- **THEN** 响应支持按 revision、证据来源/时间和稳定错误关联问题，但不包含任何可重放认证材料、完整 endpoint、用户路由或完整配置

#### Scenario: 证据已过期

- **WHEN** 持久化 selection 曾为 direct 但证据超过 TTL 或刷新失败
- **THEN** 常规入口显示 stale/unverified 和上次成功时间，不把 last-known-good 或客户端缓存显示为当前实时事实

### Requirement: Windows 与 macOS 必须遵守同一运行契约

Windows 和 macOS 常规应用 MUST 使用相同 managed 配置、enrollment、后台生命周期、服务快照、授权门禁、Provider/governance/controller/verifier 状态机、path evidence 新鲜度、降级、恢复和资源状态语义。平台只读 `PathProbe`、系统工具、秘密存储和 Provider 适配可以不同，但不得改变可观察结果；平台能力缺失 MUST 只降级对应 path/managed 能力。

#### Scenario: 两端使用相同类型配置启动

- **WHEN** 已 enrollment 的 Windows A 与 macOS B 分别通过常规入口启动
- **THEN** 两端均完成心跳、服务快照、目录拉取和真实 managed config/authorization/path 状态展示，并在无模型时继续运行

#### Scenario: 一端缺少只读平台能力

- **WHEN** 某平台无法读取 handshake 或 route 状态而另一平台可以正常探测
- **THEN** 两端使用相同稳定状态 schema，受限端只把相应 evidence 标记为 unavailable/degraded，不尝试提权或阻止其他运行时域
