# ADR-0007：受管网络 Provider 与路径发现边界

## 状态

已接受，2026-07-26。

## 决策

TunnelMinion 的首个 L3 网络闭环采用 `observe → plan → apply → verify → rollback/recover`
Provider 协议，不提供通用命令执行。Windows 使用独立 tunnel service，macOS 使用固定绝对
工具路径、独立配置目录和实际 `utunN` 映射；两端都只管理具备本地账本与实时系统指纹双重
证据的资源。

Provider 不导入或接管 `HomeMac`、B 当前 `utun4` 和手写配置。平台命令成功不是完成证据；
必须重新读取接口、地址、peer、route、握手与目标探测。部分成功按逐步回执回滚到父 revision，
所有权变化时停止自动清理。

首版 endpoint 只来自管理员显式配置或节点可验证的 WireGuard 观测。Coordinator 看到的控制
连接地址不能推断 WireGuard UDP mapping；独立 STUN socket 也不能推断 WireGuard socket。
STUN、端口映射和通用 NAT 穿透保持非目标。

relay 方向选择独立身份、认证、隔离和容量预算的不透明 packet relay，禁止匿名裸 UDP relay，
也不把普通 Coordinator 或现有 B 静默设为受信 hub。在三节点证据完成前，系统只能报告
`degraded`；若无法证明协议和 DoS 边界，relay 数据面拆为独立 change。

## 理由

- Windows 官方 tunnel service 与 macOS `wg-quick`/`wireguard-go` 的生命周期、权限和接口命名
  不同，平台差异必须留在 Provider 内，核心只消费结构化计划和回执。
- 配置文件、服务、接口、地址和 route 无法组成跨操作系统原子事务，显式 saga 与父 revision
  比“覆盖配置后看退出码”更可恢复。
- B 的真实 `utun4` 进程不暴露手写配置位置，A/B 又都有 Mihomo 宽路由；依据名称或更具体路由
  自动接管会突破用户资源边界。
- STUN 是候选发现工具而非完整穿透方案，且 socket 映射不能跨 socket 推断。
- 受信 hub 实现较简单但扩大明文信任与 forwarding/防火墙前置；不透明 relay 更符合节点私钥
  不离开本机的边界，但必须先证明专用协议安全。

## 后果

- 真实 A/B 写入前必须再次确认地址、host route、独立接口名、`18889/udp` 的 Murus 规则和
  完整回滚计划；当前只读扫描不构成授权。
- Provider fake 必须模拟权限不足、响应丢失、逐步失败、验证失败、回滚失败、名称变化和崩溃
  恢复，不能等真机阶段才发现契约缺口。
- 生产 endpoint 不在本 change 切换；`8787`、`8082`、`HomeMac`、B `utun4` 和 static peer
  始终保留。
- relay 可能成为后续独立 change，不得为勾选任务而实现未认证转发。
