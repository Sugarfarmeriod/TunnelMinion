## Context

`manage-wireguard-connectivity` 已实现 Provider、治理和 direct 路径控制，但 relay spike 只有方向性
结论：选择不持有节点私钥的不透明 packet relay，拒绝匿名裸 UDP、受信 hub 和复用普通
Coordinator。当前没有第三节点、线协议、抗滥用实现或真实性能证据，因此 relay 必须作为独立
安全敏感数据面交付。

参与者包括节点 Agent、独立 relay 进程、Coordinator 控制面和本机管理员。模型不参与 relay
身份、候选、授权、路由或切换决定；它只能解释确定性证据。relay 能看到 network/node 元数据、
连接时序和流量大小，但只能转发已经由 WireGuard 端到端加密的 packet。

## Goals / Non-Goals

**Goals:**

- 在独立第三节点运行专用 relay 数据面，普通 Coordinator 和生产 A/B 不承担转发。
- 在允许转发前验证节点身份、network、relay 授权、会话有效期和目标节点。
- 对 datagram 大小、认证前流量、每节点/network/会话并发、速率、带宽与全局容量设硬上限。
- 让路径控制器只在实际 relay 数据面、handshake、route 与目标探测联合成功后标记 `relayed`。
- 支持管理员启用、撤销、密钥轮换、relay 离线、容量耗尽和 last-known-good 恢复。
- 用隔离三节点证据比较 direct/relayed 的延迟、吞吐、中断和资源成本。

**Non-Goals:**

- 不实现匿名 UDP 转发、通用代理、端口转发、任意目标寻址或公网开放转发。
- 不终止 WireGuard 隧道、不持有节点私钥、不解密隧道内业务流量。
- 不复用 Coordinator Agent/Admin API 端口，不自动启用 IP forwarding 或修改防火墙。
- 不实现 STUN/UPnP/NAT-PMP/PCP，不宣称识别或穿透所有 NAT 类型。
- 不在生产 A/B 上直接验收 relay；未完成隔离证据前不切换生产路径。

## Decisions

### 1. relay 是独立进程、身份和监听

relay 使用独立可执行入口、数据目录、服务身份和管理员显式配置的监听地址。Coordinator 只发布
经过管理员启用和能力验证的 relay 元数据，不转发 packet。节点默认不具备 relay 能力，角色从
`none → capable → active` 的变化必须产生审计和路径 revision。

否决方案：把 Coordinator 加一个 UDP handler。该方案混合控制面与高流量数据面，扩大 DoS、
部署和密钥边界。

### 2. 先用协议 spike 在 QUIC DATAGRAM 与 TLS framed stream 间定案

首个实现任务必须用相同身份、隔离和容量预算比较：

- QUIC DATAGRAM：保留 datagram 语义，具备连接级加密、地址验证和拥塞控制，但引入 QUIC
  实现依赖与路径 MTU 约束；
- TLS 1.3 framed stream：实现和审计较简单，但 head-of-line blocking 可能损害隧道质量。

协议定案必须记录 threat model、互操作 fixture、最大 frame、重放/乱序语义、断连恢复和性能
证据。证据不足则 change 停在设计/fixture 阶段，不退化为裸 UDP。无论选择哪种，外层连接只
承载已经加密的 WireGuard packet。

### 3. 认证先于转发

relay 服务端使用管理员固定的服务身份；节点固定 relay 身份摘要。节点在已建立的安全连接内提交
短期 Coordinator assertion，relay 离线验证签名、audience、network/node、relay identity、
有效期和 nonce。认证前只接受定长握手消息并应用严格字节/时间预算，不分配可转发会话。

会话映射键为 `network_id + source_node_id + target_node_id + session_id`。目标必须同属一个
network、在线且 policy 明确允许；节点不能提供任意 IP/端口。重连产生新 session，过期 session
不可恢复或重放。

否决方案：共享 bearer token 或仅按源 IP 识别。两者都不能可靠绑定 node/network，也难以撤销。

### 4. 固定二进制 envelope 与硬容量预算

数据 envelope 只包含版本、消息类型、session ID、单调序号、目标 node ID 和 opaque payload；
字段与最大长度固定，未知版本/类型/额外字段一律拒绝。payload 上限必须扣除外层与 WireGuard
开销，禁止分片放大。

至少实施以下预算：认证超时、空闲/绝对 session TTL、每节点和每 network 会话数、每会话
datagram/秒与字节/秒、全局并发/内存/带宽、单 datagram 大小和有界发送队列。超限必须 fail
closed，返回稳定错误并记录脱敏计数，不能无限缓存或向未验证地址放大。

### 5. relayed 是实际验证结果，不是控制面声明

节点路径控制器只有在 relay 会话已认证、目标节点已绑定、WireGuard handshake 新鲜、期望 host
route 存在且目标服务探测成功时才选择 `relayed`。direct 持续失败达到阈值后才尝试 relay；
relay 失败恢复 last-known-good/static/degraded。direct 达到恢复窗口并完成实际验证后才释放
旧 relay 会话。

### 6. 最小数据与审计

relay 不记录 packet payload、私钥、完整配置或可重放 assertion。审计只保存 relay/session
摘要、network/node、决策、稳定错误、计数、字节桶和时间。高基数指标设上限并按 TTL 清理。

## Risks / Trade-offs

- [自研 relay 协议产生安全缺陷] → 先固定最小 envelope/状态机和攻击 fixture，协议定案前不写
  公网监听实现；优先复用成熟 TLS/QUIC 库而不自研密码学。
- [relay 成为反射或带宽放大器] → 地址验证、认证先于转发、同 network 目标映射、输入输出预算
  和无任意地址字段。
- [外层可靠流造成 head-of-line blocking] → 在隔离三节点中与 QUIC DATAGRAM 对照，未达预算
  不进入实现。
- [QUIC 依赖和 UDP 防火墙增加部署复杂度] → 独立依赖组、固定版本、显式端口与预检，不修改
  Murus/系统防火墙。
- [元数据泄露] → 文档明确 relay 可见 network/node、时序和大小；最小日志与 TTL 清理。
- [路径抖动或双路径重复] → 复用 direct 控制器的失败阈值、恢复窗口、最小驻留与单并发锁。
- [第三节点不可用] → 保留 static/degraded 和 last-known-good，不把 Coordinator 称作 relay。

## Migration Plan

1. 只提交协议 threat model、fixture 和两种传输 spike，不部署监听。
2. 选择协议后实现纯本机 fake transport、认证、隔离和容量门禁。
3. 在临时第三节点以非生产 network/端口部署，管理员单独配置防火墙。
4. 验证三节点 direct/relayed、撤销、容量、离线和恢复，保存脱敏前后证据。
5. 证据达到预算后才允许在测试 network 发布 `active` relay；生产迁移另需明确授权。
6. 回滚时撤销 relay 角色、停止独立进程、删除可证明自有的会话/凭据并恢复 static/degraded；
   不修改 A/B 现有 WireGuard 和生产服务。

## Open Questions

- QUIC DATAGRAM 与 TLS framed stream 哪个在目标网络和 Python 运行时达到安全/性能预算？
- 第三节点的操作系统、托管位置、管理员和可开放测试端口是什么？
- relay 服务身份使用私有 CA 证书还是管理员固定公钥；轮换与恢复窗口如何配置？
- 隔离验收的延迟、吞吐、内存和切换中断预算由谁批准？
- 是否需要多 relay 选择；首版默认只实现单 active relay，避免选路复杂度提前扩张。
