## Context

TunnelMinion 当前把 WireGuard 当作用户预先提供的数据面：A 的 `HomeMac` 与 B 的手写配置已经
稳定承载 Gateway、Coordinator 和模型访问。Coordinator 已有稳定 node/network 身份、修订、
撤销和签名公钥，操作层已有 L0～L4、批准、预授权、租约、验证与恢复，但 WireGuard 写操作仍
被确定性拒绝。

本 change 是首个 L3 系统配置闭环。它必须同时处理 Windows WireGuard 官方客户端/tunnel
service、macOS 命令行流程、管理员权限、密钥、地址/路由冲突、控制面离线、两端部分成功和
卸载恢复。模型只可解释状态或生成不带权限的建议，不能构造配置、选择路由、批准或调用
Provider。

## Goals / Non-Goals

**Goals:**

- 建立平台无关、可模拟、可审计的 `NetworkProvider` 计划/应用/验证/回滚边界。
- 让 Coordinator 确定性分配地址、交换公钥/候选 endpoint、发布签名配置修订并收敛节点确认。
- 在独立受管接口上验证直连优先、明确 relay、last-known-good 与控制面离线降级。
- 让首次创建、敏感变化和删除经过本机 L3 批准，并允许批准策略范围内的幂等自动修复。
- 证明任何失败、恢复和卸载都不会修改或删除 `HomeMac`、B 手写配置、现有防火墙和用户路由。

**Non-Goals:**

- 不实现 Linux/n2n Provider、公共 Coordinator、企业 RBAC、DNS、任意子网路由或局域网扫描。
- 不承诺通用 NAT 穿透；首版只使用经过本机策略允许的显式/受验证候选 endpoint。
- 不自动修改 Murus、Windows 防火墙、端口转发、IP forwarding 或第三方 VPN 配置。
- 不把 Coordinator API 进程默认配置成 relay，也不在本 change 中切换生产 A/B 数据面。
- 不允许模型执行 L3 操作或把聊天文本、记忆、Playbook 命中变成网络授权。

## Decisions

### 1. Provider 使用 plan/apply/verify/rollback，而不是通用命令执行

核心只依赖固定结构的 `NetworkProvider`：

- `observe()`：读取接口、地址、peer、路由、握手和所有权状态；
- `plan(desired, observed)`：生成有界、可哈希且不含私钥的差异；
- `apply(plan, authorization)`：只执行注册过的原子步骤并返回逐步回执；
- `verify(expected)`：重新读取操作系统状态，不能接受 Provider 自报成功；
- `rollback(receipt)` / `recover()`：按反向回执或所有权账本恢复。

Windows/macOS 适配器调用已安装的官方 WireGuard 工具和服务，命令/参数由代码固定。拒绝使用
Shell 字符串、模型生成配置或让核心直接判断平台命令。相比“一次写完整配置文件”，逐步回执
能识别部分成功并进行精确回滚。

### 2. 观察用户资源与管理自有资源是两个不可跨越的模式

Provider 把资源分为：

- `observed-user`：只读展示，永不作为写/删除目标；
- `managed-owned`：具有 network/node、Provider、接口名、创建 nonce、公钥、配置哈希和系统
  资源指纹的 TunnelMinion 自有资源；
- `ownership-conflict`：记录存在但系统指纹不匹配，只能停止并给出人工建议。

首版不提供“导入后接管用户现有接口”。创建名称使用专用前缀和独立配置目录；地址池必须与
当前接口、路由和 Coordinator 已分配地址均不冲突。任何删除都同时要求本地账本与实时系统
指纹匹配。相比依赖接口名前缀，双重所有权证据能抵抗名称复用和用户手工替换。

### 3. 私钥本地生成，Coordinator 只保存最小公共网络元数据

每个受管 network/node 的 WireGuard 私钥在所属节点通过固定 Provider 生成并保存到操作系统
秘密存储或 ACL 受限的 Provider 必需文件；普通 SQLite 只保存秘密引用。Coordinator 只保存
公钥、地址租约、允许的 host route、候选 endpoint、keepalive 建议、配置修订和脱敏状态。

控制面不得接收私钥、预共享密钥、完整用户路由表、物理网卡清单或任意配置正文。密钥轮换作为
新配置修订和 L3 操作处理，旧/新 key 必须有明确切换与失败回滚窗口。

### 4. 地址分配和配置发布使用事务修订与签名 envelope

Coordinator 在 network 内用事务分配单节点 host address，拒绝重叠、保留地址、跨 network
租约和地址池变化中的静默重编号。每份 desired config 绑定 network/node、配置 revision、
父 revision、公钥集合、host routes、候选、有效期和策略摘要，并使用固定指纹的 Coordinator
Ed25519 key 对域分离 payload 签名。

Agent 先验证 key 指纹、签名、目标 node、父 revision、协议和预算，再保存 pending revision。
只有 Provider 验证成功后才提交 applied acknowledgement；乱序、重复和响应丢失按 revision 与
幂等键收敛。不能验证的配置不会进入 Provider。

### 5. L3 批准授权“变化范围”，不授权模型或任意未来配置

以下变化必须在受影响节点本机展示确定性 diff 并批准：首次创建接口、扩大地址/route 范围、
更换公钥、启用/更换 relay、切换生产用途和删除资源。批准绑定 node/network、Provider、
接口前缀、地址池、允许 routes、relay policy、配置 revision/父 revision、有效期和批准人。

同一批准 policy 内，仅限保持地址/route/peer 上限且所有权仍匹配的幂等修复可以自动执行。
超出任一维度、授权撤销/过期或另一节点没有对应批准时停止在 `awaiting_authorization`。这满足
同一所有者可减少重复点击，同时避免把一次批准升级为永久任意网络管理权。

### 6. 连接状态来自真实握手与探测，不来自 Coordinator 声明

路径状态机至少包含：

`unconfigured → awaiting_authorization → applying → probing → direct | relayed |
degraded → rolling_back | ownership_conflict`

Agent 只尝试本机策略允许且 Coordinator 认证来源可解释的候选 endpoint。`direct` 必须同时有
新鲜 WireGuard handshake、目标 host route 和受预算的应用层/ICMP-independent 探测；
`relayed` 必须沿专用 relay 实际验证并显示额外信任/性能边界。切换使用失败阈值、稳定窗口和
hysteresis，避免短暂丢包导致路径抖动。

相比只看 `latest_handshake`，组合验证可以区分“握手存在但路由/服务不可用”。Coordinator
保存的是节点上报的脱敏观测，不是成功事实的最终权威。

### 7. relay 是显式角色，机制必须先通过独立 spike

relay 不复用普通 Coordinator Agent/Admin API 监听器。候选实现必须在 spike 中比较：

- 受信 WireGuard hub：实现简单，但 relay 可见解密后的节点间流量，并需要预配置 forwarding；
- 不透明 UDP datagram relay：不终止 WireGuard 加密，但协议、映射、DoS 和部署复杂度更高。

在 threat model、性能预算和三节点隔离验收通过前，不确定最终机制。无论选择哪种，relay 主机
必须由管理员显式启用并预先满足防火墙/转发条件；TunnelMinion 首版只验证前置条件，不修改
系统防火墙。没有可验证 relay 时状态保持 `degraded`，不得把 Coordinator 路径伪装为回退。

### 8. 控制面离线保留 last-known-good，不主动拆网

Agent 保存最后一次已签名且 Provider 已验证的 applied config、所有权账本和路径状态。Coordinator
离线时：

- 已工作的 managed 隧道继续运行并标记 control-plane stale；
- 不应用新地址、公钥、route 或 relay；
- 本地撤销/紧急停止仍可执行，恢复器与 static peer 不依赖模型；
- 配置超过策略允许离线期后不自动删除，只停止声称其实时受管状态。

相比“失联即清理”，保留 last-known-good 避免控制面故障反而切断修复路径。

### 9. 配置应用采用节点级 saga，不承诺跨操作系统原子事务

Coordinator 先生成共同 revision，各节点独立批准和应用。只有所有必需节点验证成功后，
revision 才进入 `active`。任一节点失败时，已应用节点按回执回滚到父 revision；回滚失败进入
`manual_intervention`，不得继续发布后续 revision。

配置锁按 network/node 串行化；取消只在安全检查点生效。审计记录计划哈希、授权 ID、步骤、
系统回执摘要、验证、回滚和错误，不记录私钥或完整配置。

### 10. 真实迁移从并行测试接口开始

实施按以下顺序推进：

1. fake Provider/Coordinator 完成无网卡的正常、并发、部分失败和恢复测试；
2. Windows/macOS `observe-only` 记录现有 A/B 不含秘密基线；
3. 用不冲突地址、独立接口名和隔离数据目录创建 managed A/B 测试隧道；
4. 验证直连、控制面离线、密钥轮换、单端失败、回滚、崩溃恢复和完整卸载；
5. 在隔离三节点环境验证选定 relay，而不是让生产 A/B 兼任 relay；
6. 清理测试资源并证明 `HomeMac`、B 手写配置、8787、8082、Murus 和用户路由前后不变。

生产 endpoint 切换不属于本 change。回滚始终先恢复父 revision，再只删除指纹匹配的测试资源。

## Risks / Trade-offs

- [Windows/macOS WireGuard 生命周期和权限语义不同] → 先做命令/API spike，Provider 契约测试
  与真机适配测试分开，权限不足结构化失败。
- [错误 AllowedIPs 或 route 可能切断网络] → 首版只允许单节点 host route，拒绝默认路由和
  非批准子网；应用前后保存路由摘要并从请求节点独立验证。
- [地址租约冲突] → Coordinator 事务唯一约束加 Agent 本机冲突预检；冲突不自动换地址重试。
- [两端部分成功] → revision saga、父配置、逐步回执、反向回滚和 manual intervention 状态。
- [relay 扩大信任边界或性能成本] → 显式角色、机制 spike、带宽/并发预算、可见状态和独立验收。
- [控制面或签名 key 被攻破] → 固定指纹、域分离签名、目标/父修订绑定、本地 L3 policy 和最终
  Provider diff 校验；Coordinator 不能单独授权写入。
- [自动修复演变成无限重试] → 单并发、指数退避、失败上限和所有权冲突熔断。
- [清理误删用户资源] → 双重所有权证据；不匹配只报告，不提供 force-delete 自动路径。

## Migration Plan

1. 只合入协议、数据模型、fake Provider、安全架构测试和评估集。
2. 合入 `observe-only` Windows/macOS Provider，真实 A/B 仍保持零写入。
3. 在新分支和隔离数据目录启用 managed 测试接口；每个写阶段单独提交和远端恢复点。
4. 完成直连与故障矩阵后再进入 relay spike/隔离三节点验收。
5. 更新 ADR、威胁模型、数据分类、安装/卸载和人工恢复手册。
6. 全部门禁和真机清理通过后归档 change；生产迁移另建 change 或由用户再次明确授权。

## Open Questions

- A/B 测试地址池和 B 的 UDP 监听端口由哪一段现有策略允许？实施前必须由只读冲突扫描和用户
  确认决定，不能把文档示例当授权。
- relay 采用受信 hub 还是不透明 datagram relay？需先用 spike 比较机密性、部署和性能。
- Windows 官方客户端、tunnel service 和 macOS 当前命令流程中，哪些操作可提供最可靠的
  原子替换/回滚回执？需在不修改现有接口的 sandbox fixture 中验证。
- 是否需要 STUN/端口映射发现？首版不得把未经验证的 NAT 穿透假设写成既定能力。
