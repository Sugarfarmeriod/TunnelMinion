## Context

`package-manual-node-runtime` 已能生成锁定、可移动的 macOS arm64 one-folder 包，并把程序、生产数据
和 SecretStore 分离。2026-08-01 真实 A/B 首次替换时，ad-hoc 签名的冻结 Gateway 进程正常存活并
拥有 `10.77.0.1:8787` 监听器，但 Windows A 建立 TCP 后收不到 HTTP 响应。macOS Application
Firewall 日志把该 flow 记录为 `Enqueuing flow without processing queue`；恢复原 `python3.12`
Gateway 后，A 立即重新得到预期 `401`。

当前 B 没有可用 codesigning identity，`notarytool` 可用，Gatekeeper 拒绝当前 ad-hoc artifact，
防火墙管理需要管理员交互。Apple 官方说明，没有处理首次入站提示时连接会继续被拒绝；面向 Mac
App Store 外分发的软件应使用 Developer ID，并在现代 macOS 上完成公证。当前用户只要求个人 A/B
节点可用，尚未决定购买/配置 Apple Developer Program 身份还是只授权当前机器。

本 change 是 `package-manual-node-runtime` 的部署前置项。它不能通过降低 Gateway 健康标准、关闭
防火墙或改写 Murus/WireGuard 来“通过”验收。

参考：

- https://support.apple.com/guide/mac-help/mh27485/mac
- https://developer.apple.com/macos/distribution/
- https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution

## Goals / Non-Goals

**Goals:**

- 在实现前通过显式决策门选择且只选择一种首发信任路线。
- 让受信任 macOS Gateway 包从 A 端稳定返回无 token `401`，并在版本替换后保持可诊断。
- 区分进程所有权、监听器所有权、系统信任和 peer 可达性，禁止弱证据冒充端到端健康。
- 对所有管理员/Keychain/Apple 凭据操作提供明确授权、确认、审计、执行后验证和安全回退。
- 保持生产配置、SecretStore、数据库、WireGuard、route、Murus 和模型进程不变。

**Non-Goals:**

- 不关闭 macOS Application Firewall，不自动创建通配例外，不管理 Murus。
- 不采购 Apple Developer Program、不导出签名私钥、不把公证凭据写入仓库、日志或运行包。
- 不实现 Windows 签名、图形安装器、自动升级、LaunchAgent/Daemon 或开机自启。
- 不以本机自身 WireGuard 地址的 HTTP hairpin 作为硬依赖，也不要求 B 本地启动时 A 永久在线。
- 不改变 Gateway token、HTTP 协议、Coordinator 或模型生命周期。

## Decisions

### 1. 首个任务是硬决策门，不并行交付两套生产路线

实现前输出两份最小 spike 证据：

- `local-firewall-authorization`：当前用户通过系统提示或 Firewall Options 明确允许清单中精确匹配的
  已验证 executable；记录管理员交互、版本升级后的身份行为和可撤销步骤。
- `developer-id-notarized`：验证 Developer ID Application identity、hardened runtime、签名顺序、
  ZIP/PKG 公证与 ticket 校验；私钥和公证认证只存在于批准的 Keychain/CI secret store。

用户必须选择一条首发路线。当前没有签名 identity 时，Developer ID 路线只能形成可执行准备清单，
不能声称已通过。决策未完成则后续实现和生产切换均停止。

否决方案：同时实现两条路线。它扩大安全表面和验收矩阵，也会掩盖当前个人节点真正需要的最小边界。

### 2. 信任针对已验证 artifact 身份，不针对任意路径或进程名

信任记录使用版本化 schema，至少包含 trust mode、package ID、清单摘要、入口文件 SHA-256、代码
签名 designated requirement/CDHash 的脱敏摘要、验证时间和状态；不保存证书私钥、公证密码或完整
本机路径。安装器先验证运行包清单，再进行信任预检。

本机授权路线只允许把清单中的当前 executable 交给系统 UI/受批准的管理员动作，不接受目录、glob、
进程名或未验证副本。Developer ID 路线同时验证签名链、hardened runtime、notarization ticket 和
Gatekeeper assessment；签名后的分发摘要与未签名可重复 payload 摘要分层记录。

否决方案：对 `python`、整个版本目录或所有未来 `tunnelminion` 二进制建立宽泛允许规则。它无法
证明获准的正是已审计 artifact。

### 3. 系统信任变更必须由人明确授权，默认命令只读

新增的 trust preflight/status 默认只调用只读的 `codesign`、`spctl` 和防火墙状态查询并输出稳定
错误码。任何添加/移除应用防火墙条目、导入证书、签名或提交公证的动作必须：

1. 展示操作对象的 package ID 与摘要，不展示秘密；
2. 获得用户对具体动作的明确确认；
3. 通过系统 UI、管理员终端或批准的 CI 身份执行；
4. 再次读取系统状态并生成审计证据；
5. 失败时不启动生产 Gateway，保留原服务并提供撤销步骤。

运行时不得请求、缓存或传递管理员密码。公证凭据不得出现在命令行、进程记录或构建日志中。

### 4. Gateway 健康拆成四层，生产验收以 peer 证据收口

状态模型区分：

1. `process_owned`：PID、启动时间、executable 和实例身份匹配；
2. `listener_owned`：同一进程拥有配置的 WireGuard 监听地址；
3. `system_trust`：所选信任路线对当前 artifact 已验证；
4. `peer_reachable`：批准的 A/B 验收器从 peer 建连，无 token 请求得到 `401`。

B 本地 `runtime start` 可以在前三层通过后报告进程已运行，但 peer 证据缺失时必须显示
`peer_unverified`，不得把 Gateway 宣称为生产可用。peer 探针只发送无 token 请求，不读取 Gateway
SecretStore；证据绑定 package ID、peer 节点 ID、响应状态、延迟和时间预算，不保存完整响应正文。

macOS 对自身 WireGuard 地址缺少可用 hairpin，因此本地 HTTP 失败不能退化为笼统 `healthy=true`。
反过来，A 暂时离线也不能导致 B 杀死已验证的自有进程；这两种状态必须分开表达。

### 5. 每次版本替换重新评估信任，不继承未经证明的结论

新 package 先并行落地并验证清单。Developer ID 路线可以在 designated requirement 与 ticket 均
有效时复用发布者信任，但仍必须生成新 artifact 证据和 peer 验收。本机授权路线必须通过 spike
证明 macOS 对新路径/新 CDHash 的行为；若不能稳定继承，就把每版人工许可列为显式升级步骤。

新包未通过 system trust 或 peer `401` 时，安装状态不得把它标为 accepted。控制器停止新包并切回
上一程序指针，但不回滚 SQLite、节点身份或秘密；随后确认旧 Gateway 恢复 `401`。

### 6. A/B 证据必须同时证明可用性与不变性

验收前后固定采集：package/入口摘要、信任状态、A 到 B 的 TCP/HTTP、Gateway 进程身份、Murus
配置 SHA-256、WireGuard 接口和稳定 route 子集、配置/SecretStore 元数据摘要、8082 与零自启动项。
含缓存与 expiry 的完整 route 输出只能作为辅助证据，不能用其易变哈希直接宣称配置被修改。

## Risks / Trade-offs

- [本机授权每个版本都重新提示] → spike 必须验证升级身份；若无法稳定继承，在文档和状态中明确
  `authorization_required`，不静默卡住请求。
- [Developer ID 需要付费账户和外部凭据] → 把身份可用性设为硬门禁，凭据仅由用户批准的 Keychain/
  CI secret store 提供，仓库永不生成或保存。
- [签名破坏逐文件可重复摘要] → 分离未签名 payload 清单与签名后 distribution 清单，两者分别验证。
- [监听器存在但系统仍阻断] → 状态分层，生产 accepted 必须有 peer `401`。
- [peer 暂时离线造成误回滚] → peer 未验证与本地进程失败分开；只有明确替换事务才按预算回滚。
- [为验收误改生产网络] → 前后摘要与精确写入授权；禁止更改 Murus、WireGuard、route 或关闭防火墙。

## Migration Plan

1. 在非生产端口和临时数据目录复现当前 ad-hoc 入站行为，保存只读信任基线。
2. 分别验证两条路线的前置条件、用户交互、版本替换和撤销方式，提交决策证据。
3. 用户选择首发路线后，更新本 design 的确定决策并提交；未选择则停止。
4. 实现 trust manifest、只读 preflight/status、所选授权/签名适配器和分层健康证据。
5. 在隔离包上完成首次许可、后续版本、拒绝/过期/篡改、peer 离线与安全回退矩阵。
6. 固定真实 A/B 前置摘要；停止旧 Gateway，切换候选，完成 A 端 `401` 和常驻验收。
7. 任一关键项失败，停止可证明自有的新进程，恢复旧 Python Gateway 并复核 `401`；不改生产数据。
8. 通过双平台回归、秘密扫描、签名/许可证据和 OpenSpec 门禁后，再解除
   `package-manual-node-runtime` 的 B 节点阻断。

## Open Questions

- 用户选择 `local-firewall-authorization` 还是 `developer-id-notarized` 作为首发路线？
- 若选择 Developer ID，哪个 Apple Developer team/CI 环境有权持有证书和公证凭据？
- peer 验收由人工 A CLI、独立 acceptance runner，还是未来 Coordinator 触发？首版推荐独立 A CLI，
  避免把尚未配置的 Coordinator 变成运行前置依赖。
