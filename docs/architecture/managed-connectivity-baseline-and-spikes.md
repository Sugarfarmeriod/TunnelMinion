# 受管连接只读基线与技术 spike

## 结论

2026-07-26 的首轮工作只执行了只读查询，没有创建接口、写配置、改路由、改防火墙或占用新端口。
脱敏真机结果保存在
`evaluations/platform/managed-connectivity-readonly-baseline-2026-07-26.json`。

当前不能进入真实网络写入，原因不是 WireGuard 本身不可用，而是以下边界尚未满足：

- Windows A 与 macOS B 都运行 Mihomo TUN；常见 RFC1918 候选池会被现有宽路由覆盖。新增更具体
  host route 虽可在技术上覆盖它们，但这会改变用户现有选路，必须单独展示和批准。
- B 当前通过 `wireguard-go utun` 运行 `utun4`。普通账户可看到接口和进程，但不能读取 peer，
  进程参数也不包含手写配置位置；在 B 所有者确认位置和启动编排前，恢复方案不完整。
- 用户已在 Murus 放行 `18881-18889`，但首轮只证明 `18889/udp` 当前没有监听冲突，尚未证明
  Murus 规则包含 UDP 入站。端口放行与允许 TunnelMinion 创建监听是两项不同授权。

因此地址池与 `18889/udp` 仅是候选，不是授权。`HomeMac`、B 的 `utun4`、Gateway `8787`、
模型 `8082`、Murus 和现有 route 仍是禁止写入目标。

## Windows Provider spike

Windows 官方文档提供两条生命周期路径：

- 每个配置可以安装为独立的 `WireGuardTunnel$<name>` 服务，并由标准服务管理器启停；
- Manager Service 监控 `%ProgramFiles%\WireGuard\Data\Configurations\`，把 `.conf` 转成
  DPAPI 加密的 `.conf.dpapi`，限制 ACL 后删除原明文。

官方还说明 tunnel service 启动时创建适配器、停止时销毁适配器；DPAPI 配置通常要求
Administrator 或 Local System 才能使用 `wg` 查询。这与 A 上普通权限读取 peer 返回
`permission_denied` 一致。

Provider 结论：

1. 首版使用独立、revision 绑定的 tunnel service，不通过 Manager UI 接管用户配置。
2. 安装、启动、停止、卸载必须是不同步骤并分别保存服务与适配器回执。
3. 官方接口没有承诺“配置文件 + 地址 + route”的跨步骤原子替换；更新必须保存父 revision，
   失败时按已确认步骤逆序恢复，不能只相信命令退出码。
4. `.conf` 明文只能出现在 ACL 受限临时位置，并在 Manager/Service 已接管或失败后立即验证删除；
   生产实现前还要在 fake runner 中覆盖明文残留、服务已存在、停止超时与响应丢失。
5. `HomeMac.conf.dpapi` 始终属于 `observed-user`，不能进入 install、uninstall 或 update 计划。

依据：

- [WireGuard for Windows Enterprise Usage](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)
- [WireGuard Windows tunnel service source](https://git.zx2c4.com/wireguard-windows/tree/tunnel/service.go)

## macOS Provider spike

B 已安装 Homebrew `wireguard-tools 1.0.20250521`，但非登录 SSH PATH 没有包含
`/opt/homebrew/bin`；Provider 必须使用固定绝对路径。当前数据面由 `wireguard-go utun`
创建，实际接口是 `utun4`。

官方语义表明：

- macOS 的 `wireguard-go` 不能使用任意接口名；可请求 `utun` 让内核分配，并通过
  `WG_TUN_NAME_FILE` 获取实际名称；
- `wg-quick up` 同时创建接口、配置地址/MTU/route 并可执行 hook，`down` 会拆除接口；
- `wg syncconf` 可以只更新差异并尽量不打断 peer 会话，但不负责 `wg-quick` 管理的地址和 route。

Provider 结论：

1. 禁止 `PreUp`、`PostUp`、`PreDown`、`PostDown`、`SaveConfig` 和动态配置路径。
2. 使用独立配置目录、固定绝对工具路径和 `WG_TUN_NAME_FILE` 记录稳定账本到实际 `utunN` 的映射。
3. peer-only 更新可评估 `wg syncconf`；地址、route、接口生命周期仍必须拆成独立步骤并实时验证。
4. 当前 B 手写启动流不是 `wg-quick <known path>`，不能据接口名推断配置或所有权；首版不得导入。
5. fake fixture 必须覆盖 utun 名称变化、工具不在 PATH、权限不足、hook 拒绝和 `syncconf`
   成功但 route 未更新。

依据：

- [wireguard-go 官方说明](https://git.zx2c4.com/wireguard-go/about/)
- [wg-quick(8)](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)
- [wg(8)](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8)

## relay 机制 spike

| 维度 | 受信 WireGuard hub | 不透明 packet relay |
|---|---|---|
| 机密性 | hub 是 WireGuard peer，可看到解密后的节点流量 | 只转发端到端加密的 WireGuard packet，不持有节点私钥 |
| 系统前置 | 需要 hub 配置 peer、IP forwarding、route 和防火墙 | 需要独立认证、会话映射、反放大、速率/容量和过期回收 |
| 部署 | 复用 WireGuard 工具，较简单 | 必须实现并审计专用数据面协议，不能复用 Coordinator API |
| DoS | 可由 WireGuard peer 身份限流，但 hub 网络栈暴露更大 | 未认证 UDP relay 极易被滥用；必须先认证再允许转发 |
| 性能 | 内核/成熟 userspace 路径通常更直接 | 多一层封装与用户态转发，需要三节点实测 |
| 信任说明 | 管理员必须接受 hub 可见明文 | relay 仍可见元数据、时序和流量大小，但看不到隧道明文 |

选择：TunnelMinion 不采用“匿名裸 UDP 转发”，也不把 B 或普通 Coordinator 静默变成受信 hub。
首选方向是具有独立身份与容量预算的不透明 packet relay，转发已经加密的 WireGuard packet；
在三节点协议、安全与性能证据完成前只保留契约和显式 `degraded` 状态，不宣称已经具备 relay。

该选择借鉴 DERP 的安全边界而不是照搬其实现：节点私钥不离开本机，relay 只盲转加密 packet。
若阶段 8 无法在独立协议内证明身份、隔离和 DoS 边界，应拆成独立 change，而不是退化成匿名
UDP 转发。

参考：

- [WireGuard 协议论文](https://www.wireguard.com/papers/wireguard.pdf)
- [Tailscale DERP 技术说明](https://tailscale.com/docs/reference/derp-servers)

## endpoint、STUN 与 NAT 映射 spike

首版只接受两个来源：

1. 管理员显式配置并经本机策略允许的 endpoint；
2. 节点从 WireGuard 实际状态观察到、且能绑定来源和有效期的 endpoint。

Coordinator 从 HTTP/SSH 控制连接看到的源地址或端口不能当作 WireGuard UDP endpoint，因为
它通常不是同一个 UDP socket 或 NAT mapping。STUN 能返回 NAT 分配的地址和端口，但
[RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html) 明确指出 STUN 只是 NAT traversal
工具，不是完整解决方案。对 WireGuard 来说，独立 STUN socket 的映射不能证明 WireGuard
socket 的映射；官方 Windows tunnel service 和当前 macOS `wireguard-go` 流程也没有为
TunnelMinion 提供安全复用该 socket 的接口。

因此首版不实现 STUN、UPnP、NAT-PMP、PCP 或自动端口映射，不声称通用打洞能力。只有后续
Provider 能证明“同一 UDP socket 发现 + 双向验证 + 防火墙边界”时，STUN candidate 才能进入
新 change。当前路径选择必须把显式 endpoint 叫作“候选”，只有新鲜 handshake、host route
和目标探测同时通过后才叫 `direct`。

## 地址与端口停止门禁

只读扫描器采用以下判定：

1. 收集接口地址和 route，但持久报告只保存必要冲突摘要与完整快照的 SHA-256；
2. 排除默认路由后，检查候选 pool 是否与任一已有接口地址或更具体 route 重叠；
3. 对候选首个 host 执行系统 route lookup，记录实际命中的接口；
4. 检查目标 UDP 端口是否已监听，但不把“未监听”解释为防火墙已放行；
5. 任一宽 TUN route、所有权未知、完整恢复路径未知或防火墙不可读都产生停止门禁。

本轮三个候选均命中 Mihomo route，因此结果是
`no_conflict_free_ipv4_private_pool_proven`。下一次真实写入授权界面必须展示具体 host
address、双方 `/32` route、原命中 Mihomo route、接口名、`18889/udp`、回滚步骤和前后哈希。
