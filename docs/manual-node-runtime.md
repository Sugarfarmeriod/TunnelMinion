# 手工节点运行包

TunnelMinion 节点运行包面向当前用户安装，不创建 Windows Service、计划任务、启动文件夹项、
macOS LaunchAgent 或 LaunchDaemon。执行 `runtime start` 后进程会脱离当前终端常驻；注销、关机或
重启后不会自动恢复，需要用户再次手工执行 `runtime start`。

Gateway 是节点可选承担的角色，不是 macOS B 专属组件。A、B 或其他节点只要需要通过受控接口
向 peer 提供工具或操作服务，都可以在自己的非秘密 profile 中启用 Gateway；只使用本地页面的
节点不必启用它。

## 文件放在哪里

程序、普通配置、运行数据和秘密彼此分离：

- 版本化程序由 `runtime-package` 放在当前用户的 `TunnelMinionRuntime` 标准应用数据目录；
- `runtime-profile.json` 放在当前用户的 TunnelMinion 标准配置目录，只记录数据目录、启用组件和
  本地端口等非秘密字段；
- SQLite、节点身份、组件状态和日志放在 profile 指向的 TunnelMinion 数据目录；
- 模型 API key、Gateway token 和 Coordinator refresh 默认保存在 Windows Credential Manager
  或 macOS Keychain。只有用户已经显式选择 `restricted-file` 后端时，秘密才会进入数据目录内的
  权限受限文件；它们不会进入程序目录、profile、命令输出或构建清单。

程序升级和只移除程序都复用并保留同一数据目录和 SecretStore。真正删除数据仍使用现有的
`tunnelminion uninstall`，并要求显式确认。

当前 A/B 生产布局的例子如下，路径只用于说明边界，不应写入构建清单：

- Windows A 的程序版本位于当前用户 `%LOCALAPPDATA%\TunnelMinion\TunnelMinionRuntime\versions`，
  profile 和默认数据位于 `%LOCALAPPDATA%\TunnelMinion\TunnelMinion`；
- macOS B 的程序版本位于 `~/Library/Application Support/TunnelMinionRuntime/versions`，profile 位于
  `~/Library/Application Support/TunnelMinion/runtime-profile.json`；
- macOS B 继续复用既有 `~/Working-Env/tunnelminion-mvp/data` 作为生产数据目录，其中的
  `restricted-file` SecretStore 不会被复制进 `Application Support` 下的程序目录。

## 第一次配置与手工启停

仅运行本地应用：

```text
tunnelminion runtime configure
tunnelminion runtime start
tunnelminion runtime status
tunnelminion runtime stop
```

要让同一节点同时运行独立 Gateway，先确保既有数据目录中已有有效 `gateway.json` 和对应
SecretStore，再把 Gateway 加入非秘密 runtime profile：

```text
tunnelminion runtime configure --enable-gateway
tunnelminion runtime start
tunnelminion runtime status
```

`runtime configure --enable-gateway` 不会生成 token，也不会改防火墙、WireGuard、route 或 Murus；
它只声明“手工 start 时也启动已经配置好的 Gateway”。如果 `gateway.json` 不存在，状态会明确显示
`gateway_unconfigured`，本地应用仍可独立运行。

Gateway 只依赖配置的 endpoint 可路由，不依赖某一种 VPN。当前 A/B 实验使用 WireGuard 地址；
普通局域网、企业 VPN 或其他可路由地址具有相同语义。地址分配、路由和防火墙放行由部署者负责，
TunnelMinion 不自动发现节点，也不自动修改网络策略。

## 模型由谁启动

模型是 TunnelMinion 之外的外部服务。`runtime start` 只启动本地应用和按 profile 启用的 Gateway，
不会寻找、启动、停止、安装或更新 `llama-server` 等模型进程。`runtime status` 会对已配置 endpoint
做有界只读检查；模型不可达时应显示 `unavailable`，确定性资源工具和 Gateway 生命周期仍独立工作。

如果模型由用户稍后手工开启，再执行一次 `runtime status` 或本地应用的模型验证即可刷新可达状态，
不需要重启 TunnelMinion。删除或改写生产模型配置不是运行状态检查的一部分。

## 理解本地状态与 peer 验收

`runtime start` 和 `runtime status` 报告本地 lifecycle。Gateway 的 `running` 表示运行包记录的
进程身份成立、配置的监听器确实由该受管进程拥有，并且稳定窗口结束后仍成立。它不表示任意 peer
已经可以访问。只有独立 peer 对当前 package/入口发出无 Authorization header 的有界请求并得到
`401`，候选才是 `peer_reachable` 且可以标记 accepted；尚未验收和不可达分别报告
`peer_unverified`、`peer_unreachable`。

监听器所有权不是“端口有人占用”。runtime 会联合核对 PID、启动时间、executable、组件参数和
实例身份，并验证 socket 属于该进程；无法证明时报告 `listener_ownership_unverified`，其他进程
占用端口时不会误报成功。macOS 不使用本机访问自身私网地址的 HTTP hairpin 作为本地就绪前置，
因此 hairpin 超时不会把实际可供 peer 访问的自有 Gateway 误报为 `startup_unstable`。

`startup_timeout_seconds` 是从组件启动开始计算的 monotonic 总 deadline。单次探针、重试等待和
稳定窗口都消耗同一预算，不会再把多次连接超时叠加成远超配置值的等待。peer 离线不改变本地
所有权结论，也不阻止 `status` 或对已证明自有进程执行安全 `stop`。

## 状态、日志和分层排错

逐组件 PID 记录、生命周期状态与日志位于 profile 指向的数据目录下的 `runtime` 子目录。日志使用
有界轮转，不记录认证 header、token、refresh、私钥、标准输入或完整远端响应。`status` 只输出
稳定错误码、摘要和日志位置；它不会读取秘密正文。

排查顺序是：先看 `runtime-package status` 的当前程序版本，再看 `runtime status` 的组件所有权和
模型依赖，最后查看对应的 `runtime/logs/local.log` 或 `runtime/logs/gateway.log`。随后从另一台
获准节点探测配置的 Gateway endpoint：无 token `401` 证明应用层已响应；超时只能说明端到端路径
不可达，可能涉及监听、路由、防火墙或网络，不能仅凭缺少日志武断归因。不要直接删除 PID 记录；
身份不匹配时保留现场，由 `ownership-conflict` 防止误杀其他进程。

防火墙日志是可选诊断。只有部署者已经提供安全只读接口和权限时，才保存时间、动作、进程/端口
和规则标识的脱敏摘要；没有安装 Murus、使用其他防火墙、没有日志接口或当前账户无读取权限时，
本地 lifecycle 与 peer 验收仍可运行。TunnelMinion 不需要读取完整规则、数据包正文或秘密。

## 安装和切换版本

先从发布位置校验并并行放置新包，不改变当前版本：

```text
tunnelminion runtime-package stage --package-root <包目录> --manifest <manifest.json>
```

然后按顺序手工停止、切换、启动并检查：

```text
tunnelminion runtime stop
tunnelminion runtime-package activate --package-id <package-id>
tunnelminion runtime-package status
<status 中 current_program_directory 里的 tunnelminion> runtime start
<status 中 current_program_directory 里的 tunnelminion> runtime status
```

新版本健康或 peer 验收失败时，先用新版本执行 `runtime stop`，再对切换前已经验证的 package ID
执行 `runtime-package activate`，随后用该程序目录启动并重新取得 peer `401`。也可以恢复切换前
已固定命令与身份的 direct 入口，但不能把旧源码 checkout、损坏的 `.venv` 或碰巧存在的系统
Python 当作可靠退路。切换只改变程序指针和受管进程，不回滚 SQLite、checkpoint、节点身份、
Gateway token、Coordinator refresh、普通配置或 SecretStore。

## 只移除程序

先停止所有受管组件，再从安装目录之外的一份已验证运行包执行：

```text
tunnelminion runtime stop
tunnelminion runtime-package remove
```

Windows 不允许正在执行的 `.exe` 删除自身，因此 `remove` 应从发布包或另一份外部运行包调用。
成功输出会明确标记 `data_preserved` 和 `secret_store_preserved`。如果进程状态无法确认，切换和移除
都会 fail closed，不会猜测进程归属或强杀。

## macOS Gateway 入站信任

macOS Application Firewall 与 Murus 是两套独立控制。冻结运行包第一次在 WireGuard 地址监听时，
系统可能允许 TCP 握手却把入站 flow 留在许可队列；此时 `lsof` 会显示 `10.77.0.1:8787` 正在监听，
但 peer 的 HTTP 请求会超时。不能仅凭 PID 或监听器把这种状态报告为 Gateway 可用，正式验收必须
从已授权 peer 发起无 token 请求并得到 `401`。

`runtime-package` 不会自动添加应用防火墙例外，也不会修改 Murus、VPN、WireGuard 或 route。
当前 macOS 机器由用户通过系统界面对经过清单验证的精确 executable 人工许可；新 package 或入口
摘要变化后需要重新核对。人工许可不会创建 LaunchAgent、LaunchDaemon 或其他开机自启。
Developer ID、hardened runtime 与公证分发不属于当前个人 A/B 交付。

排查时先区分三层结果：

1. `runtime status` 证明受管进程身份和本地生命周期；
2. runtime 的 listener ownership 证明配置监听器属于该进程，端口级 `lsof` 只能作为辅助；
3. 获准 peer 访问 `/v1/capabilities` 得到 `401` 才证明所用网络、防火墙和 Gateway 端到端可达。

2026-08-08 的真实 A/B 验收中，runtime-managed 候选在终端脱离后报告本地 `running`，配置 endpoint
连续三次从 Windows peer 返回无 token `401`，并通过重复 start、新会话 status、正常 stop 与 direct
恢复。验收结束后按计划恢复切换前 direct 入口，未改 accepted 指针、生产配置、SecretStore、模型、
客户防火墙、route 或自启动项。脱敏结果见
[runtime health 最终证据](../evaluations/platform/runtime-health-production-final-2026-08-08.json)。

## 明确延期的能力

- 局域网自动发现（如 mDNS/Bonjour 或广播扫描）需要独立 change；当前由部署者显式提供 endpoint。
- macOS、Windows 和第三方产品的跨厂商防火墙日志采集适配需要独立 change；日志始终是可选诊断。
- Coordinator 真机 enrollment/sync 延期，不是本地 `start/status/stop` 或本轮 peer 验收的前置。
