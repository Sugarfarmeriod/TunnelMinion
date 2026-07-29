# 受管连接 A/B 真机验收

本报告记录 `manage-wireguard-connectivity` 第 10 阶段在 Windows A 与 macOS B 上的真实执行。
报告只保存公钥哈希、计划哈希、脱敏状态和结论，不保存 WireGuard 私钥、完整配置、完整路由表
或防火墙规则正文。

## 隔离范围

| 项目 | Windows A | macOS B |
|---|---|---|
| 逻辑接口 | `tmn-accept-a` | `tmn-accept-b` |
| 实际接口 | `tmn-accept-a.r1` | `utun7` |
| 测试地址 | `10.253.0.2/32` | `10.253.0.1/32` |
| 对端 host route | `10.253.0.1/32` | `10.253.0.2/32` |
| 公钥哈希 | `sha256:ebffe91e95c1e85306198291d6bccd8910c8544b9c632aa00751c9c8165c1040` | `sha256:396b2de0386a275ca5da44256380691123fff58bdf6c3a7a922a906cbf04333f` |
| 数据目录 | `.data/managed-acceptance/a-retry2` | 隔离的 managed acceptance 目录 |

签名配置和两端本机 L3 授权共同绑定 `10.253.0.0/24`、精确 `/32` host route、接口、
revision、所有权、Mihomo 宽路由观测指纹和 B 的 UDP `18889`。生产 `HomeMac`、`utun4`、
Gateway `8787`、模型 `8082`、Murus 和 static endpoint 均不属于 Provider 的写入范围。

## 创建与联合验证

| 检查 | 证据 | 结论 |
|---|---|---|
| B 创建 | plan `sha256:e07c975919a6088e9e6fe8d9516440bf7cbe954d9f2eaf858139e7743fcb6b49`；`applied`、`verified` | 通过 |
| A 创建 | plan `sha256:c1d11a269c1ce0d1d0af25895bf82c619cbc33e7f1818793692b03f3fce110da`；`applied`、`verified` | 通过 |
| 双方密钥 | A 观测的 peer 与 B 本机公钥一致；B 观测的 peer 与 A 本机公钥一致 | 通过 |
| 外层 endpoint | A 通过既有 `HomeMac` 路径使用 `10.77.0.1:18889`；B 观测 A 为 `10.77.0.2` 的临时源端口 | 通过 |
| WireGuard 握手 | 双方 `latest handshake` 新鲜，且收发计数均大于零 | 通过 |
| 精确路由 | A/B 均存在唯一对端 `/32` host route，原 Mihomo 宽路由保留 | 通过 |
| 目标探测 | B 证明 `10.253.0.1:18888` 真实监听；A 收到 `HTTP 200`；B 日志记录来源 `10.253.0.2` | 通过 |

路径可以标记为 `direct`。规范要求的“新鲜握手 + 预期 host route + 请求节点目标探测”
已经同时成立。Murus 最初没有允许新 `utun` 上来自 `10.253.0.2` 的 TCP 入站；用户增加精确
地址限制后探测通过。临时 HTTP 服务每次探测后均已停止，`18888` 无残留监听。

## 真实失败与恢复证据

| 场景 | 实际现象 | 安全结果 |
|---|---|---|
| macOS 验证失败 | point-to-point 地址解析最初未识别 `/32` | Provider 回滚；修复解析后重新批准新 plan |
| Windows 单端 apply 失败 | 官方客户端把 revision 配置安装为版本化运行时接口，初版未建立双重所有权证据 | 拒绝提交账本并执行逆序回滚 |
| Windows 应用后枚举延迟 | 服务创建成功后，接口、公钥或路由尚未收敛 | 增加有界等待；不把短暂缺失当作成功 |
| Windows 回滚异步卸载 | 卸载命令返回时服务仍在收敛 | 增加有界轮询与重试，必须确认接口和服务消失 |
| 进程中断后恢复 | 未完成 operation journal 保留逐步系统回执 | `recover` 逆序恢复为 `rolled_back`，无测试 route 残留 |
| 错误 plan hash | 本机批准 hash 与实时预览不同 | 在任何写入前拒绝 |
| Coordinator 离线 | A/B 使用已签名且未过期的本地 envelope 执行 | 不依赖模型或在线 Coordinator，仍由本机 L3 门禁决定 |
| 所有权缺失/权限不足 | 非管理员进程无法读取实时公钥，实时状态不能与账本双证据匹配 | 清理预览拒绝，不按接口名猜测删除 |
| 目标响应丢失与恢复 | 停止 `18888` 后 A 的目标探测失败；重新启动同一有界监听后恢复为 `HTTP 200` | 路径结果跟随独立目标探测，不把 WireGuard 握手误当应用可用 |
| 节点公钥轮换生命周期 | 真实 SQLite 控制面中旧 key 为 `active`，新 key 先为 `pending`；激活后状态为 `retired/active` | 不静默覆盖 active key，且拒绝重新激活 retired key |

节点公钥轮换使用临时 SQLite 控制面和只存在于进程内的替换私钥，不更换已建立隧道的本机
私钥；它证明 Coordinator 的 `pending → active/retired` 生命周期，不宣称完成生产密钥迁移。

## 清理与不变性

| 检查 | 结果 |
|---|---|
| A Provider remove | `applied`、`verification_succeeded=true` |
| A 幂等 remove | `already_absent`、`writes_performed=false` |
| A 系统残留 | 版本化服务、适配器和 `10.253.0.1/32` route 均不存在 |
| B Provider remove | `applied`、`verification_succeeded=true` |
| B 幂等 remove | `already_absent`、`writes_performed=false` |
| B 系统残留 | `utun7`、`10.253.0.2/32` route、UDP `18889` 和 TCP `18888` 均不存在 |
| 隔离数据 | Windows 与 macOS 的 managed acceptance 根目录均已删除 |
| Windows 生产路径 | `WireGuardTunnel$HomeMac` 为 `Running`，`HomeMac` 为 `Up` |
| macOS 生产路径 | 原 `utun4` 为 `UP,POINTOPOINT,RUNNING` |
| 生产服务 | B 的 `10.77.0.1:8787` 与 `*:8082` 仍在监听 |
| static 回退 | A 仍能通过 `10.77.0.1` 的原路径访问 B 并执行只读复核 |

受管资源先清理 A、再清理 B。两端第二次调用都不生成 plan、不执行写入，证明 Provider 清理
幂等。真实系统复核没有发现测试接口、host route 或监听残留；生产接口和服务保持原状态。
Murus 规则正文没有机器可读权限。操作者选择保留手工增加的
`TCP 10.253.0.2 → 10.253.0.1:18888` 规则；当前测试地址、接口和监听均不存在，因此规则没有
当前目标，但若将来复用相同地址则会重新生效。该差异不属于 TunnelMinion Provider 所有，
不能记为“防火墙前后不变”。

## relay 结论

本 change 没有可引用的真实三节点 packet relay 数据面证据，因此不执行 relay 验收，也不让
生产 A、B 或 Coordinator 静默承担 relay。relay 协议、认证、容量、DoS、安全与三节点矩阵已
拆分到 `build-isolated-packet-relay`；本次无 relay 时保持 `static/degraded`，不得宣称
`relayed`。
