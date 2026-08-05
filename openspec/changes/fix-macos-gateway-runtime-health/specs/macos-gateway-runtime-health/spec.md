## ADDED Requirements

### Requirement: Gateway 本地生命周期与 peer 可达性必须分域

系统 SHALL 把 Gateway 的本地运行状态与 peer 端到端可达性表示为不同结果。`running` MUST 只表示
进程所有权、预期监听器所有权和稳定窗口通过；生产 accepted MUST 另外要求已批准 peer 的无 token
请求在预算内得到 `401`。PID 或监听器存在 MUST NOT 单独等同于 peer 可达。

#### Scenario: macOS 本机 hairpin 不可用但 peer 可达

- **WHEN** macOS runtime 拥有 Gateway 进程与配置监听器，B 本机访问自身 WireGuard 地址超时，而 A
  的无 token 请求得到 `401`
- **THEN** 本地 lifecycle 报告 `running`，A/B 验收报告 `peer_reachable`，系统不得把 Gateway 误报为
  `startup_unstable`

#### Scenario: 监听器存在但防火墙挂起 peer 请求

- **WHEN** Gateway 进程拥有配置监听器，但批准 peer 未在预算内收到 HTTP 响应
- **THEN** 本地 lifecycle 可以报告 `running`，A/B 验收 MUST 报告 `peer_unreachable`，生产候选不得
  标记 accepted

#### Scenario: 尚未运行 peer 验收

- **WHEN** 本地 Gateway 已通过进程与监听器所有权验证，但没有与当前 package/入口匹配的 peer 证据
- **THEN** 本地操作保持可用，A/B 验收状态为 `peer_unverified`，不得伪造 `peer_reachable`

### Requirement: Gateway 本地就绪必须验证监听器所有权

系统 MUST 验证配置的私网监听地址和端口由记录中的 Gateway PID 拥有，并 MUST 在稳定窗口后复核。
macOS MUST NOT 把对自身 WireGuard 地址的 HTTP 请求作为本地就绪硬依赖；无法读取监听器所有权时
MUST fail closed，且不得退化为“端口被任意进程监听即成功”。

#### Scenario: 监听器属于其他进程

- **WHEN** 配置端口正在监听，但监听 socket 的 PID 与 runtime 进程记录不匹配
- **THEN** 启动或状态报告稳定的所有权冲突，不把 Gateway 标记 running，也不终止身份不明进程

#### Scenario: 当前账户无法验证监听器归属

- **WHEN** 平台 API 与批准的固定参数降级适配器均无法证明监听器属于记录 PID
- **THEN** 系统报告 `listener_ownership_unverified`，不接受仅端口级或进程名级证据

#### Scenario: 稳定窗口内监听器消失

- **WHEN** Gateway 初次取得监听器，但在稳定窗口结束前进程退出或释放该监听器
- **THEN** `start` 报告本地启动失败并保留稳定诊断，不把短暂监听标记 running

### Requirement: 启动超时必须是有界总 deadline

系统 MUST 使用 monotonic 总 deadline 约束每个组件启动。单次探针 timeout、重试等待和稳定窗口
MUST 计入 `startup_timeout_seconds`，命令实际等待 MUST NOT 随重试次数把单次探针超时重复叠加到
预算之外，仅允许固定调度容差。

#### Scenario: 每次 readiness 探针都超时

- **WHEN** 每次探针消耗其允许的剩余时间且组件始终未就绪
- **THEN** `start` 在总 deadline 到达时返回 `startup_timeout`，不继续执行完整次数的额外探针

#### Scenario: 临近 deadline 时组件变为就绪

- **WHEN** 组件在总 deadline 前取得监听器，但剩余时间不足以完成稳定窗口
- **THEN** 系统不得越过 deadline 宣称成功，并返回稳定的启动超时结果

#### Scenario: fake clock 验证预算

- **WHEN** 测试注入 monotonic clock、探针耗时和 sleep
- **THEN** 所有分支的累计等待不超过配置预算加固定容差，且不依赖墙钟或不稳定调度

### Requirement: status 与 stop 不得依赖 peer 在线

`status` SHALL 使用本地进程身份和监听器所有权报告 lifecycle；`stop` MUST 只根据 PID、启动时间、
executable、组件参数和实例身份决定能否正常终止。peer 未验收、离线或超时 MUST NOT 阻止状态读取
或安全停止，也 MUST NOT 降低身份冲突时的 fail-closed 行为。

#### Scenario: peer 离线时查看和停止

- **WHEN** runtime 拥有 Gateway 进程与监听器，但批准 peer 当前离线
- **THEN** `status` 报告本地 running，`stop` 可按正常 checkpoint/timeout 语义终止自有进程，不先
  访问 peer

#### Scenario: 监听器消失但进程身份仍匹配

- **WHEN** 自有 Gateway 进程仍存在但配置监听器已经消失
- **THEN** `status` 报告本地健康失败，`stop` 仍可正常终止该已证明所有权的进程

#### Scenario: 进程身份冲突且 peer 可达

- **WHEN** PID 实时身份与记录不匹配，即使目标端口从 peer 看起来可达
- **THEN** `status` 报告 `ownership-conflict`，`stop` 不终止该进程，peer 结果不得覆盖本地所有权失败

### Requirement: 健康修复不得改写生产安全边界

本 change MUST NOT 自动修改 Application Firewall、Murus、WireGuard、route、Gateway 绑定、生产
配置、SecretStore、模型进程或自启动项。探针与状态输出 MUST NOT 读取或输出 token、Authorization
header、完整响应正文、完整 endpoint 或不可信异常正文。

#### Scenario: 完成隔离与真实验收

- **WHEN** 修复通过 macOS 隔离测试和真实 A/B runtime-managed Gateway 验收
- **THEN** 只有运行包进程/状态/受限日志和获明确授权的切换发生变化，Murus、WireGuard、稳定 route、
  配置、SecretStore、模型 8082 与零自启动证据保持不变

#### Scenario: peer 返回恶意或过大正文

- **WHEN** peer 验收收到非预期状态、过大正文或包含敏感样式内容的响应
- **THEN** 系统只保存稳定状态码、大小/时间摘要和脱敏错误，不把正文写入 runtime 状态或证据
