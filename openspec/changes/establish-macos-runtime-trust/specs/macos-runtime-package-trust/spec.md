## ADDED Requirements

### Requirement: 当前机器信任必须使用显式人工授权

个人 A/B 的 macOS Gateway trust mode SHALL 为 `local-firewall-authorization`。系统 MUST 在生产
替换前展示已验证 package 的身份摘要并等待用户通过 macOS 系统 UI 对精确 executable 人工授权；
不得自动添加、删除或扩大防火墙许可。

#### Scenario: 尚未取得当前机器授权

- **WHEN** 已验证 ad-hoc package 尚未获得当前机器精确 executable 的人工许可
- **THEN** 验收报告 `authorization_required`，不自动添加许可且不停止切换前已验证可用的 Gateway

#### Scenario: 请求未来分发信任

- **WHEN** 用户要求 Developer ID、hardened runtime 或公证分发能力
- **THEN** 当前 change 不生成伪签名或索取外部凭据，并要求进入独立的分发信任 change

### Requirement: 信任必须绑定已验证 artifact

系统 MUST 先验证运行包清单，再把信任证据绑定到 package ID、manifest SHA-256 和入口 SHA-256。
系统 MUST NOT 通过目录、glob、进程名或未验证副本向任意未来二进制授予信任。

#### Scenario: artifact 在信任后被替换

- **WHEN** 当前 package、manifest 或入口文件摘要与已记录信任证据不匹配
- **THEN** 系统把信任状态报告为 `artifact_mismatch`，不启动生产 Gateway，也不沿用旧版本结论

#### Scenario: 新版本落在新路径

- **WHEN** 新 package 通过清单验证但路径或入口摘要发生变化
- **THEN** 系统不自动继承旧许可结论，先只读核对并在必要时要求新的人工许可和 peer `401`

### Requirement: 系统信任写入必须获得明确授权

添加或移除 macOS 应用防火墙条目 MUST 由用户对精确动作明确授权。自动流程 SHALL 默认只执行
只读预检，MUST NOT 获取、缓存、回显或记录管理员密码。

#### Scenario: 本机防火墙许可需要管理员操作

- **WHEN** 当前机器路线需要把已验证 executable 加入允许入站连接列表
- **THEN** 系统展示 package ID 与脱敏摘要并暂停，由用户通过系统 UI 或明确批准的管理员步骤完成，
  随后只读复核结果

#### Scenario: 用户拒绝授权

- **WHEN** 用户拒绝或取消精确 executable 的防火墙许可动作
- **THEN** 系统保持原策略和既有 Gateway 不变，记录 `trust_authorization_declined` 且不尝试绕过

### Requirement: 当前机器信任验收必须由 peer 证明入站许可有效

生产候选的当前机器信任验收 MUST 由已批准 peer 在预算内完成无 token 请求并得到 `401`；PID、
进程名、许可条目或监听器存在 MUST NOT 单独证明入站许可有效。本 requirement 不定义 runtime 本地
生命周期或 peer 状态机。

#### Scenario: 监听器存在但应用防火墙挂起请求

- **WHEN** Gateway 进程拥有 WireGuard 监听器，但 peer TCP 连接后没有在预算内收到 HTTP 响应
- **THEN** 信任验收报告 `peer_unreachable` 或 `authorization_pending`，不把许可标记为已验证，并
  保留切换前已验证入口

#### Scenario: peer 完成无秘密探测

- **WHEN** 指定 peer 对候选 Gateway 发出无 Authorization header 的有界能力请求并收到 `401`
- **THEN** 系统记录 package、peer、状态码、延迟和时间摘要，不读取 SecretStore 或保存响应正文

### Requirement: 版本替换失败必须恢复服务且保留数据

新 macOS package 未通过清单、精确许可或 peer 验收时，系统 SHALL 停止可证明属于候选的进程并
允许恢复切换前已验证入口。回退 MUST 复用原数据目录与 SecretStore，MUST NOT 回滚数据库、节点
身份、Gateway token、WireGuard、route、Murus 或模型进程，也不得假设旧开发环境仍可启动。

#### Scenario: 新包首次入站许可失败

- **WHEN** 候选 Gateway 启动后未通过精确许可或 peer `401` 门禁
- **THEN** 系统停止候选、恢复切换前已验证 Gateway，并要求 peer 再次得到 `401` 后才报告回退成功

#### Scenario: 无法证明候选进程所有权

- **WHEN** 候选停止阶段出现 PID 复用或 executable/启动时间/实例身份不匹配
- **THEN** 系统 fail closed，不终止身份不明进程、不删除状态证据，并进入人工处理

### Requirement: 信任与验收证据不得泄露秘密

信任状态、审计和 A/B 证据 MUST NOT 包含管理员密码、Gateway token、Coordinator refresh、模型
API key、Authorization header 或完整远端响应。证据 SHALL 使用摘要、稳定错误码、计数和受限
路径标识。

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
