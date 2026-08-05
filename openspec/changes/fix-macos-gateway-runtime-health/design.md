## Context

`package-manual-node-runtime` 当前把本地应用和 Gateway 都交给同一个 `RuntimeComponentHealthProbe`。
本地应用探测 `127.0.0.1` 没有问题；Gateway 探测配置中的 WireGuard 地址。真实 macOS B 对自身
`10.77.0.1:8787` 没有可用 HTTP hairpin，因此每次 0.5 秒 HTTP 超时与 0.1 秒重试间隔叠加，名义
30 秒的 `startup_timeout_seconds` 实际约 185 秒才退出。此时 Windows A 已能稳定得到 `401`，但
runtime 把 Gateway 记录为 `startup_unstable`。

不能把 Gateway 探针简单改成“进程还在”或“端口存在”：首次防火墙未授权时，进程和监听器都存在，
但 A 的 HTTP flow 被挂起。当前机器人工授权已经解决系统信任前置；本 change 只修复本地生命周期
和 peer 验收的职责划分。

当前生产 B 由正式候选 direct `gateway --data-dir data` 提供服务，已脱离终端且 A 得到 `401`；旧
Python 开发环境缺少依赖，不能作为可靠回退。修复实现与测试不得在具备已验证替代入口前停止该进程。

## Goals / Non-Goals

**Goals:**

- 让本地 runtime 准确判断自己是否拥有一个稳定运行并拥有预期监听器的 Gateway 进程。
- 让 peer 可达性由独立 A/B 验收证据表达，不让 peer 离线破坏本地 `status`/`stop`。
- 让启动预算成为从命令开始计时的真实 monotonic deadline。
- 同时防止 hairpin 假阴性和“只看监听器”假阳性。
- 保持现有进程所有权、秘密、数据目录、零自启动和网络不写入边界。

**Non-Goals:**

- 不自动修改 Application Firewall、Murus、WireGuard、route 或 Gateway 绑定。
- 不实现 Developer ID/公证或新的 trust manifest；当前机器人工许可由独立 trust change 负责。
- 不要求 A、Coordinator 或模型在 B 执行本地 `start/status/stop` 时在线。
- 不新增 Gateway HTTP endpoint，不读取 token，不把 peer 证据写入长期记忆。
- 不改变 Windows 本地应用的环回 HTTP 健康语义或创建开机自启。

## Decisions

### 1. 本地生命周期与端到端验收使用两个结果域

`ManualLifecycleManager` 的 `running` 只表示本地生命周期成立：进程身份匹配、预期监听器由该进程
拥有、稳定窗口后仍成立。A/B acceptance runner 单独报告 `peer_unverified`、`peer_reachable` 或
`peer_unreachable`；只有 `peer_reachable` 且无 token 请求得到 `401` 才能把生产候选标记 accepted。

本地 runtime JSON 不持久化或伪造 peer 结论。真实 A/B 报告把本地 runtime 状态、package/入口摘要、
人工许可状态和 peer 结果组合起来。这样 B 的日常 `start/status/stop` 不依赖 A 永久在线，也不需要
新增跨节点写协议。

否决方案：把 peer 探测塞进 B 的 `runtime start`。它会让 A/Coordinator 变成本地启动硬依赖，并在
peer 临时离线时错误回滚健康自有进程。

### 2. Gateway 本地就绪使用进程专属监听器所有权，不使用自身 WireGuard HTTP

本地应用继续使用环回 HTTP。Gateway 使用新的有界 `GatewayListenerOwnershipProbe`：验证配置地址/
端口存在、监听 socket 属于记录中的 PID，并在稳定窗口后复核所有权。macOS 适配器优先使用当前
账户可读的进程专属 socket 信息；若 Python API 权限不足，使用固定 executable、固定参数、无 shell
的 `lsof -nP -a -p <pid> -iTCP@<host>:<port> -sTCP:LISTEN` 降级。实现前必须用隔离进程验证两条路径；
均不可用时返回稳定的 `listener_ownership_unverified`，不得退化为端口级成功。

监听器所有权只证明本地进程就绪，不证明 Application Firewall 或 peer 可达。A 端 acceptance runner
仍必须发送无 Authorization header 的有界 `/v1/capabilities` 请求并得到 `401`。

否决方案：把配置 host 改成 `127.0.0.1` 做自检。Gateway 没有环回监听器，临时新增监听会扩大攻击面
并改变既有协议边界。

### 3. 启动预算是 monotonic 总 deadline

`start` 为每个组件计算 `deadline = monotonic() + startup_timeout_seconds`。每次探针的 timeout、重试
sleep 和 stable window 都裁剪到剩余预算；剩余时间小于等于零立即返回 `startup_timeout`。测试注入
fake clock/sleep，证明墙钟耗时不超过预算加固定调度容差，而不是按“重试次数 × 单次超时”增长。

探针接口从无上下文 bool 扩展为有界结果，至少包含 `ready` 与稳定错误码；不包含异常正文、完整
命令或 endpoint。已有 fake 探针提供兼容适配，避免生命周期测试依赖真实 socket。

### 4. `status` 和 `stop` 优先保证所有权安全

`status` 先验证 PID、启动时间、executable、组件参数和实例 ID，再检查本地监听器所有权。peer 尚未
验收或暂时离线不改变该所有权结论。`stop` 只使用进程记录与实时身份决定能否发送正常终止信号，
不得先访问 peer，也不得因 listener/peer 不可达而失去安全停止能力。

身份冲突仍然 fail closed；监听器消失但进程仍属于 runtime 时，`status` 报告本地失败，`stop` 仍可
正常终止该自有进程。停止不强杀，继续遵守 checkpoint 与 shutdown timeout。

### 5. 真实验收以可回退的候选切换收口

实现先在 fake、环回 fixture 和 macOS 隔离数据目录验证，再构建新 package。真实 B 切换前必须确认
当前 direct Gateway 仍由 A 得到 `401`，并准备一个已验证可恢复入口。只有新 runtime-managed Gateway
完成本地 start/status/stop、终端脱离、重复 start 和 A peer `401` 后，才能替换当前入口。

任何失败都停止可证明属于候选的进程，恢复切换前已验证入口并复核 A `401`；不得依赖已损坏的旧
Python `.venv`，不得回滚 SQLite、节点身份、配置或 SecretStore。

## Risks / Trade-offs

- [监听器所有权适配器在 macOS 权限不足] → 先做进程专属 API/lsof 隔离 spike；两者都失败时返回
  `listener_ownership_unverified`，不接受端口级弱证据。
- [把 local running 误解为生产可用] → CLI/文档明确本地 lifecycle 与 A/B accepted 分域，生产门禁
  始终要求 peer `401`。
- [deadline 修复引入测试时序波动] → 注入 monotonic clock、probe 和 sleep，使用确定性预算断言。
- [peer 离线时留下不可用服务] → 本地不强杀；外部验收报告 `peer_unreachable`，替换事务按明确预算
  恢复切换前入口。
- [真实切换失去回退] → 不把旧开发环境当退路；每次先验证当前入口及恢复命令，再停止生产进程。

## Migration Plan

1. 为本地 readiness 结果、listener ownership 适配器和 monotonic deadline 增加 fake/单元测试。
2. 接线 Gateway 本地就绪，保留本地应用环回 HTTP 行为，更新脱敏 CLI 状态与兼容测试。
3. 在 macOS 隔离 package/数据目录验证 hairpin 不通、listener 归属、超时、PID 冲突和安全停止。
4. 运行 Windows/macOS 全量、覆盖率、秘密、OpenSpec 和打包门禁；更新运维文档与主 FigJam。
5. 固定真实 A/B 与当前 direct Gateway 基线，受控切换新 package，完成本地 lifecycle 与 A peer `401`。
6. 成功后更新 `package-manual-node-runtime` 6.3b；失败时恢复切换前已验证入口并保留证据。

## Open Questions

- macOS 当前账户下 `psutil.Process(pid).net_connections()` 是否稳定返回自有监听器？若权限不足，固定
  参数 `lsof` 将作为正式降级路径；该选择必须由隔离 spike 决定，不能凭假设固定。
- listener ownership 的跨平台公共接口是否同时替换 Windows Gateway 自身 HTTP 探针，还是首版只在
  macOS 选择平台策略？推荐保持统一接口、平台适配器分别实现，并用 Windows 回归决定迁移范围。
