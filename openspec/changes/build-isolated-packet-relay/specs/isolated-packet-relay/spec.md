## ADDED Requirements

### Requirement: relay 数据面必须独立部署
系统 MUST 将 packet relay 运行在具有独立服务身份、监听、数据目录和管理员授权的专用进程；
普通 Coordinator API 和未启用节点不得转发 packet。

#### Scenario: 普通 Coordinator 收到 relay 数据
- **WHEN** 客户端把 relay 数据发送到 Coordinator Agent/Admin API
- **THEN** Coordinator SHALL 拒绝该流量且不得创建 relay 会话

#### Scenario: 未启用节点自报 relay
- **WHEN** Agent 声称 `relay-capable` 但没有管理员启用和能力验证
- **THEN** 系统 SHALL 保持该节点非 relay 角色且不发布候选

### Requirement: relay 必须在认证后才允许转发
relay MUST 在转发前验证服务身份固定、短期节点 assertion、audience、network/node、目标节点、
relay identity、有效期和一次性会话 nonce；源 IP 或共享明文 token 不得单独构成身份。

#### Scenario: 匿名 datagram 到达 relay
- **WHEN** relay 收到没有已认证会话的 payload
- **THEN** relay SHALL 在固定认证前预算内丢弃且不得向任何目标转发

#### Scenario: 跨 network 目标
- **WHEN** 已认证节点请求向不同 network 的节点发送 packet
- **THEN** relay SHALL 返回稳定隔离错误、记录脱敏审计且不泄露目标是否存在

#### Scenario: assertion 重放
- **WHEN** 过期、错误 audience 或已使用 nonce 的 assertion 再次建立会话
- **THEN** relay SHALL 拒绝会话且不得恢复旧 session 映射

### Requirement: relay envelope 必须固定且只承载不透明 packet
协议 MUST 使用版本化、有界的 envelope，字段仅包含消息类型、session、单调序号、目标节点和
opaque payload；relay MUST NOT 接收任意目标 IP/端口，不得解密或持久化 WireGuard payload。

#### Scenario: 未知版本或超长 datagram
- **WHEN** 客户端发送未知版本、未知消息类型、额外字段或超过上限的 payload
- **THEN** relay SHALL 在分配转发缓冲前拒绝该消息

#### Scenario: 审计 relay 会话
- **WHEN** relay 记录会话建立、转发、限流或关闭
- **THEN** 审计 SHALL 只含身份摘要、计数、字节桶、稳定错误和时间，不含 payload 或可重放凭据

### Requirement: relay 必须实施分层容量与 DoS 门禁
relay SHALL 对认证前字节/时间、datagram 大小、每会话速率、每节点/network 会话和带宽、全局
并发/内存/队列/带宽及 session TTL 设置硬上限；超限 MUST fail closed 且不得形成反射放大。

#### Scenario: 单节点耗尽容量
- **WHEN** 一个节点超过会话、datagram 或带宽预算
- **THEN** relay SHALL 仅限制该主体并保留其他 network/node 的已批准容量

#### Scenario: 发送队列已满
- **WHEN** 目标离线或消费速度不足导致有界队列达到上限
- **THEN** relay SHALL 丢弃或关闭受影响 session，不得无限缓存或阻塞全局事件循环

#### Scenario: 空闲会话过期
- **WHEN** session 超过空闲或绝对 TTL
- **THEN** relay SHALL 删除映射、释放预算且拒绝旧 session ID 的后续 packet

### Requirement: relay 角色变更必须显式且可撤销
`relay-capable` 与 `active` MUST 由本机管理员启用并绑定能力验证、relay identity 和 revision；
撤销或身份轮换 SHALL 产生新路径 revision，并阻止新会话选择旧 relay。

#### Scenario: 管理员撤销 active relay
- **WHEN** 管理员撤销 active 角色
- **THEN** Coordinator SHALL 停止发布旧 relay，节点 SHALL 关闭或有界排空会话并回退到已验证路径

#### Scenario: relay identity 轮换
- **WHEN** relay 服务身份变更但节点尚未批准新摘要
- **THEN** 节点 SHALL 拒绝连接且不得静默接受新身份

### Requirement: relayed 状态必须经过端到端实际验证
系统 MUST 仅在 relay 会话已认证、目标绑定成功、WireGuard handshake 新鲜、期望 host route
存在且请求节点目标探测成功后标记 `relayed`；控制面声明或 relay 命令成功不得单独构成完成证据。

#### Scenario: direct 持续失败且 relay 验证成功
- **WHEN** direct 达失败阈值、双方允许同一 active relay 且联合 relay 验证成功
- **THEN** 路径控制器 SHALL 在新 revision 选择 `relayed` 并保留 direct 与 relay 的脱敏证据

#### Scenario: relay 可连接但目标探测失败
- **WHEN** relay 会话建立成功但 handshake、route 或目标服务任一未验证
- **THEN** 系统 SHALL 保持 static/degraded 或恢复 last-known-good，不得显示 `relayed`

#### Scenario: direct 稳定恢复
- **WHEN** relayed 期间 direct 连续成功达到恢复窗口并满足最小驻留
- **THEN** 控制器 SHALL 先验证并切换 direct，再释放旧 relay session

### Requirement: relay 必须通过隔离三节点验收
实现 SHALL 在非生产 A/B 数据面的隔离三节点环境验证协议、身份、隔离、DoS、撤销、恢复和性能；
没有第三节点证据时系统 MUST 明确报告 relay 不可用。

#### Scenario: 没有隔离第三节点
- **WHEN** 测试环境只有生产 A/B 或要求普通 Coordinator 兼任 relay
- **THEN** 验收 SHALL 停止并保持 `degraded`，不得伪造 relayed 结果

#### Scenario: 完整三节点矩阵
- **WHEN** 独立 relay 环境准备完成
- **THEN** 验收 SHALL 覆盖 direct、relayed、relay 离线、容量耗尽、跨 network、撤销和恢复，并记录
  延迟、吞吐、切换中断、CPU、内存和信任差异
