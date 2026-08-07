## Why

真实 macOS B 证明，正式 Gateway 已能让 Windows A 稳定得到 `401`，但 B 本机无法 hairpin 访问自身
WireGuard 地址，导致 `runtime start` 等待约 185 秒后把实际可服务 peer 的自有进程误报为
`startup_unstable`。现在必须修复本地生命周期与外部可达性混用的问题，同时保留“监听器不能冒充
端到端健康”的安全边界。

## What Changes

- 为 macOS Gateway 分离本地生命周期证据与 peer 端到端证据：本地只判断进程身份、监听器所有权
  和稳定窗口；peer 以 `peer_unverified`、`peer_reachable`、`peer_unreachable` 独立表达。
- 让 `runtime start` 使用真实总 deadline；单次探针耗时必须计入预算，不能把每次连接超时叠加成
  远超 `startup_timeout_seconds` 的等待。
- macOS 本机 hairpin 不可用时，不把所有权匹配且监听正常的 Gateway 误报为 failed；PID 或监听器
  单独存在也不得标记 peer accepted，真实生产验收继续要求 A 无 token请求得到 `401`。
- peer 地址与底层传输解耦：当前 A/B 环境使用 WireGuard 地址，但同一契约也适用于客户提供的局域网、
  企业 VPN 或其他可路由地址；TunnelMinion 不把 WireGuard 或自动局域网发现作为本 change 的前置。
- 防火墙日志在可安全取得时作为脱敏的可选诊断，帮助区分规则拦截、路由和监听问题；没有 Murus、
  没有日志接口或没有读取权限时，继续以真实 peer 请求判定可达性，不阻塞本地运行或 A/B 验收。
- `status` 与 `stop` 只依赖可证明的本地进程所有权，peer 离线或尚未验收不得阻止状态读取和安全停止。
- 修复后重跑 fake/集成矩阵与真实 B 的 runtime-managed start/status/stop、重复 start、终端脱离、
  新会话 stopped、手动恢复和 A peer `401`。
- 非目标：不自动修改客户管理的防火墙、VPN、WireGuard 或 route，也不实现局域网自动发现；不实现
  Developer ID/公证、Coordinator、模型生命周期、开机自启或新的 Gateway HTTP 协议。
- 非目标：不在本 change 实现 Murus、macOS、Windows 或第三方防火墙的通用日志采集适配器；该能力
  若产品化应拆成独立 change，并保持权限最小化与日志脱敏。

## Capabilities

### New Capabilities

- `macos-gateway-runtime-health`: macOS Gateway 的本地所有权/监听生命周期、真实总 deadline、独立 peer
  可达状态以及不依赖 peer 的安全 status/stop 契约。

### Modified Capabilities

无。本 change 为仍在进行的 `manual-node-runtime-operations` 提供独立修复能力，归档时由后者的收尾
任务引用，不提前改写尚未同步到主规格的 capability。

## Impact

- 影响 `tunnelminion.runtime.control`、`tunnelminion.runtime.lifecycle`、runtime 状态模型、CLI 脱敏输出
  以及相应单元/集成/A-B 验收证据。
- 不改变运行包格式、Gateway token/SecretStore、生产数据目录、模型进程、Coordinator 或客户管理的
  网络治理；部署者负责让配置的 Gateway 地址和端口可达，TunnelMinion 负责检测并报告结果。
- 当前生产 B 继续由已获人工许可的正式候选 direct Gateway 提供服务；在修复通过真实验收前不得
  假装它已经由 runtime 管理，也不得停止该入口而没有已验证回退方案。
