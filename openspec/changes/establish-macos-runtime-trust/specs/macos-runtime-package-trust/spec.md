## ADDED Requirements

### Requirement: macOS 运行包信任路线必须显式选择

系统 SHALL 在生产 Gateway 替换前要求选择一个版本化 trust mode，并 MUST 验证该模式的全部前置
条件。未选择、前置条件缺失或同时选择多个模式时，系统 MUST fail closed，且不得修改防火墙、
Keychain 或生产进程。

#### Scenario: 尚未选择信任路线

- **WHEN** 用户对只有 ad-hoc 签名且没有已确认 trust mode 的 macOS 包执行生产信任预检
- **THEN** 系统返回稳定的 `trust_mode_required`，不添加许可、不导入证书且不停止既有 Gateway

#### Scenario: Developer ID 前置身份缺失

- **WHEN** 选择的模式要求 Developer ID，但构建环境没有有效签名身份或公证认证
- **THEN** 系统返回脱敏的前置条件错误，不生成伪签名 artifact，也不回退为隐式本机防火墙例外

### Requirement: 信任必须绑定已验证 artifact

系统 MUST 先验证运行包清单，再把信任证据绑定到 package ID、入口 SHA-256 和所选模式对应的
代码签名身份摘要。系统 MUST NOT 通过目录、glob、进程名或未验证副本向任意未来二进制授予信任。

#### Scenario: artifact 在信任后被替换

- **WHEN** 当前入口文件摘要或代码签名身份与已记录信任证据不匹配
- **THEN** 系统把信任状态报告为 `artifact_mismatch`，不启动生产 Gateway，也不沿用旧版本结论

#### Scenario: 新版本使用同一发布者

- **WHEN** 新 package 通过清单验证且所选模式允许复用稳定发布者身份
- **THEN** 系统仍为新 artifact 生成独立信任证据，并要求新的 peer 端到端验收后才能标记 accepted

### Requirement: 系统信任写入必须获得明确授权

添加或移除 macOS 应用防火墙条目、导入签名身份、执行代码签名或提交公证均 MUST 由用户对精确
动作明确授权。系统 SHALL 默认只执行只读预检，MUST NOT 获取、缓存、回显或记录管理员密码、
签名私钥和公证凭据。

#### Scenario: 本机防火墙许可需要管理员操作

- **WHEN** 当前机器路线需要把已验证 executable 加入允许入站连接列表
- **THEN** 系统展示 package ID 与脱敏摘要并暂停，由用户通过系统 UI 或明确批准的管理员步骤完成，
  随后只读复核结果

#### Scenario: 用户拒绝授权

- **WHEN** 用户拒绝或取消防火墙、Keychain、签名或公证动作
- **THEN** 系统保持原策略和既有 Gateway 不变，记录 `trust_authorization_declined` 且不尝试绕过

### Requirement: Gateway 健康必须分层且由 peer 证明端到端可达

系统 SHALL 分别报告进程所有权、监听器所有权、系统信任和 peer 可达性。生产候选 MUST 由已批准
peer 在预算内完成无 token 请求并得到 `401`，才能标记为端到端 accepted；PID 或监听器存在 MUST
NOT 单独等同于 Gateway 可用。

#### Scenario: 监听器存在但应用防火墙挂起请求

- **WHEN** Gateway 进程拥有 WireGuard 监听器，但 peer TCP 连接后没有在预算内收到 HTTP 响应
- **THEN** 系统报告 `peer_unreachable` 或 `trust_pending`，不把候选标记 accepted，并保留安全回退入口

#### Scenario: peer 暂时离线

- **WHEN** 本地进程、监听器和系统信任均通过，但指定 peer 当前不可达
- **THEN** 系统报告 `peer_unverified` 而非伪造成功，且不因单次外部不可达强杀已验证的自有进程

#### Scenario: peer 完成无秘密探测

- **WHEN** 指定 peer 对候选 Gateway 发出无 Authorization header 的有界能力请求并收到 `401`
- **THEN** 系统记录 package、peer、状态码、延迟和时间摘要，不读取 SecretStore 或保存响应正文

### Requirement: 版本替换失败必须恢复服务且保留数据

新 macOS package 未通过清单、系统信任或 peer 验收时，系统 SHALL 停止可证明属于候选的进程并
允许恢复上一入口。回退 MUST 复用原数据目录与 SecretStore，MUST NOT 回滚数据库、节点身份、
Gateway token、WireGuard、route、Murus 或模型进程。

#### Scenario: 新包首次入站许可失败

- **WHEN** 候选 Gateway 启动后未通过系统信任或 peer `401` 门禁
- **THEN** 系统停止候选、恢复既有已验证 Gateway，并要求 peer 再次得到 `401` 后才报告回退成功

#### Scenario: 无法证明候选进程所有权

- **WHEN** 候选停止阶段出现 PID 复用或 executable/启动时间/实例身份不匹配
- **THEN** 系统 fail closed，不终止身份不明进程、不删除状态证据，并进入人工处理

### Requirement: 信任与验收证据不得泄露秘密

信任 manifest、状态、审计和 A/B 证据 MUST NOT 包含管理员密码、签名私钥、公证认证、Gateway
token、Coordinator refresh、模型 API key、Authorization header 或完整远端响应。证据 SHALL 使用
摘要、稳定错误码、计数和受限路径标识。

#### Scenario: 生成支持证据包

- **WHEN** 用户导出 macOS 包信任和 peer 健康诊断
- **THEN** 输出只包含允许字段与摘要，秘密扫描为零发现，且不能据此重放任何认证或管理员动作

### Requirement: 信任流程不得创建自启动或改写网络

系统 MUST NOT 因运行包信任创建 LaunchAgent/Daemon、登录项或其他自启动，也 MUST NOT 关闭应用
防火墙或修改 Murus、WireGuard、route 和 Gateway 绑定。信任前后 SHALL 保存这些边界的不变性证据。

#### Scenario: 完成当前机器许可

- **WHEN** 用户明确允许一个已验证 Gateway executable 接收入站连接
- **THEN** 只有该精确信任对象发生预期变化，自启动计数、Murus SHA-256、WireGuard 接口、稳定 route
  子集和 Gateway 配置摘要保持不变
