## Context

`package-manual-node-runtime` 已能生成锁定、可移动的 macOS arm64 one-folder 包，并把程序、生产数据
和 SecretStore 分离。2026-08-01 真实 A/B 首次替换时，ad-hoc 签名的冻结 Gateway 进程正常存活并
拥有 `10.77.0.1:8787` 监听器，但 Windows A 建立 TCP 后收不到 HTTP 响应。macOS Application
Firewall 日志把该 flow 记录为 `Enqueuing flow without processing queue`；恢复原 `python3.12`
Gateway 后，A 立即重新得到预期 `401`。

当前 B 没有可用 codesigning identity，`notarytool` 可用，Gatekeeper 拒绝当前 ad-hoc artifact，
防火墙管理需要管理员交互。用户已明确当前只要求个人 A/B 节点可用，并选择
`local-firewall-authorization`：通过 macOS 系统 UI 允许清单中的精确正式 executable。2026-08-01
复验中，Windows A 首次等待许可后得到 `401`，后续稳定约 85–100 ms。

本 change 固化该当前机器部署前置和证据。它不实现 runtime 健康状态机，不能通过降低 Gateway
健康标准、关闭防火墙或改写 Murus/WireGuard 来“通过”验收。

参考：

- https://support.apple.com/guide/mac-help/mh27485/mac
- https://developer.apple.com/macos/distribution/
- https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution

## Goals / Non-Goals

**Goals:**

- 固定当前机器人工授权为个人 A/B 首发 trust mode，不再并行实现 Developer ID 路线。
- 让获准的精确 macOS Gateway artifact 从 A 端稳定返回无 token `401`，并在版本替换后重新核对。
- 对人工防火墙许可提供明确授权、artifact 摘要、执行后验证、撤销说明和安全回退。
- 保持生产配置、SecretStore、数据库、WireGuard、route、Murus 和模型进程不变。

**Non-Goals:**

- 不关闭 macOS Application Firewall，不自动创建通配例外，不管理 Murus。
- 不实现 Developer ID、hardened runtime、公证 ticket 或签名后分发清单；这些属于未来对外分发 change。
- 不实现 Windows 签名、图形安装器、自动升级、LaunchAgent/Daemon 或开机自启。
- 不设计本机生命周期、hairpin 或 peer 状态机；这些属于 `fix-macos-gateway-runtime-health`。
- 不改变 Gateway token、HTTP 协议、Coordinator 或模型生命周期。

## Decisions

### 1. 首发路线固定为当前机器人工授权

用户已选择 `local-firewall-authorization`。当前用户通过系统提示或 Firewall Options 明确允许清单中
精确匹配的已验证 executable；TunnelMinion 只展示 package/摘要、触发有界 peer 请求并在操作后
只读复核，不自动执行防火墙写入，也不请求或缓存管理员密码。

Developer ID、公证和签名后 distribution manifest 不属于本 change。未来需要向其他 Mac 用户分发
时另开 change，再评估 Apple Developer 身份、CI 凭据、hardened runtime 和 ticket。

### 2. 信任针对已验证 artifact 身份，不针对任意路径或进程名

信任记录使用版本化 schema，至少包含 trust mode、package ID、清单摘要、入口文件 SHA-256、代码
签名 designated requirement/CDHash 的脱敏摘要、验证时间和状态；不保存证书私钥、公证密码或完整
本机路径。安装器先验证运行包清单，再进行信任预检。

本机授权路线只允许把清单中的当前 executable 交给系统 UI/受批准的管理员动作，不接受目录、glob、
进程名或未验证副本。

否决方案：对 `python`、整个版本目录或所有未来 `tunnelminion` 二进制建立宽泛允许规则。它无法
证明获准的正是已审计 artifact。

### 3. 系统信任变更必须由人明确授权，默认命令只读

所有自动检查默认只调用只读的运行包清单、防火墙状态和进程查询并输出稳定结果。任何添加/移除
应用防火墙条目的动作必须：

1. 展示操作对象的 package ID 与摘要，不展示秘密；
2. 获得用户对具体动作的明确确认；
3. 通过系统 UI 或用户明确批准的管理员步骤执行；
4. 再次读取系统状态并生成审计证据；
5. 失败时不启动生产 Gateway，保留原服务并提供撤销步骤。

运行时不得请求、缓存或传递管理员密码。

### 4. 信任验收由 artifact 身份与 peer `401` 共同收口

当前机器许可只证明系统 UI 已允许精确 executable；生产信任验收还必须由批准的 A/B 验收器从 peer
建连，并让无 token 请求得到 `401`。peer 探针不读取 Gateway SecretStore；证据绑定 package ID、
manifest/入口摘要、响应状态、延迟和时间预算，不保存完整响应正文。

PID 或监听器存在不能替代该结论。B 本机 hairpin 失败、`peer_unverified`/`peer_reachable` 状态和
`runtime start/status/stop` 的本地生命周期语义由 `fix-macos-gateway-runtime-health` 负责，本 change
不再重复定义或实现。

### 5. 每次版本替换重新评估信任，不继承未经证明的结论

新 package 先并行落地并验证清单。当前机器授权不得自动继承到未经证明的新路径或入口摘要；每个
新 artifact 都先只读核对系统状态，必要时把人工许可列为显式升级步骤，再生成新的 peer 验收证据。

新包未通过精确许可或 peer `401` 时不得标记 accepted。停止可证明属于候选的进程并恢复切换前已
验证可用的入口，但不回滚 SQLite、节点身份或秘密；不得假设旧 Python 开发环境仍可启动。

### 6. A/B 证据必须同时证明可用性与不变性

验收前后固定采集：package/入口摘要、信任状态、A 到 B 的 TCP/HTTP、Gateway 进程身份、Murus
配置 SHA-256、WireGuard 接口和稳定 route 子集、配置/SecretStore 元数据摘要、8082 与零自启动项。
含缓存与 expiry 的完整 route 输出只能作为辅助证据，不能用其易变哈希直接宣称配置被修改。

## Risks / Trade-offs

- [本机授权每个版本都重新提示] → 每版先只读核对；若无法稳定继承，在文档和状态中明确
  `authorization_required`，不静默卡住请求。
- [未来分发需要 Developer ID] → 独立 change 处理账户、签名、公证、CI 凭据和分发清单，不把外部
  凭据前置条件混入当前个人 A/B。
- [监听器存在但系统仍阻断] → 状态分层，生产 accepted 必须有 peer `401`。
- [peer 暂时离线造成误回滚] → peer 未验证与本地进程失败分开；只有明确替换事务才按预算回滚。
- [为验收误改生产网络] → 前后摘要与精确写入授权；禁止更改 Murus、WireGuard、route 或关闭防火墙。

## Migration Plan

1. 保存 ad-hoc 包、Application Firewall、Murus/WireGuard、生产配置/SecretStore 和现有入口基线。
2. 用户确认 `local-firewall-authorization`，通过系统 UI 允许精确正式 executable。
3. 从 Windows A 发出无 token 请求，保存首次与稳定 `401`、artifact 摘要和不变性证据。
4. 对每个新 artifact 重复清单验证、只读许可核对、必要的人工授权和 peer `401`。
5. 任一关键项失败，停止可证明自有的候选并恢复切换前已验证入口；不改生产数据或网络治理。
6. 更新许可、撤销、升级和故障诊断文档；严格验证、提交并在主架构图中核对授权边界。

## Resolved Decisions

- 当前个人 A/B 首发采用 `local-firewall-authorization`；Developer ID/公证延期到未来分发 change。
- peer 验收使用独立 A 端请求，不依赖尚未配置的 Coordinator。
- runtime 本地生命周期与 peer 状态分层属于独立 health fix。
- 回退目标是切换前已验证入口；旧 Python Gateway 不再被视为可靠恢复前提。
