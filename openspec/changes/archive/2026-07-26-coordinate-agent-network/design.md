## Context

当前 Windows A 与 macOS B 通过用户手工维护的 WireGuard 网络互通。TunnelMinion 在每个节点
保存静态 peer endpoint 和应用 token，Agent 先直连对方 Gateway 获取节点摘要与能力，再调用
只读工具或提交受治理的操作。该方案已经证明数据面和安全操作闭环，但节点集合、地址、凭据、
能力和服务没有统一的新鲜度模型：

- 增加或撤销节点需要分别修改多处本地配置；
- Agent 在直连前不知道节点是否已离线、endpoint 是否已更新或工具版本是否兼容；
- 资源面板无法浏览跨节点服务目录，只能为单次问题即时采集；
- 静态 peer 配置缺少统一修订、过期和撤销传播；
- 过大的旧 `deliver-minimum-viable-mesh` 同时包含自动 WireGuard、Linux、中继和前端，不能作为
  本阶段实现单位。

本 change 面向单所有者私有网络，Coordinator 是自托管的受信控制面。首轮 A/B 验收继续使用
现有 `HomeMac` 和 `10.77.0.1` 数据面，不申请系统网络管理权限。节点所有者、开发者和本地
管理员是主要参与者；模型 Provider、远端工具正文和服务业务正文均在 Coordinator 信任边界外。

## Goals / Non-Goals

**Goals:**

- 以一次性 enrollment token 建立稳定节点身份、可撤销 refresh 凭据和短期访问 assertion。
- 用版本化心跳、能力摘要和完整服务快照维护可收敛的节点/服务目录。
- 按稳定节点 ID、当前在线状态、授权、平台和协议版本动态选择远端工具。
- 保持 Coordinator、Agent、Gateway 和本地页面均可独立故障和安全降级。
- 让无模型环境仍可注册、同步、查看目录和使用确定性资源 API。
- 为未来自动 WireGuard、Linux、多人共享和其他网络 Provider 保留明确协议边界。

**Non-Goals:**

- 不创建、修改、删除或分发 WireGuard 密钥、接口、peer、路由与防火墙规则。
- 不让 Coordinator 代理 Tool/Operation Gateway、HTTP 临时共享流量或模型请求。
- 不实现 NAT 穿透、点对点路径选择、中继、虚拟地址分配或 n2n。
- 不实现 Linux Agent、安装包、独立 React 前端、公共 SaaS、多租户计费、SSO 或企业 RBAC。
- 不集中保存模型密钥、长期记忆、对话、完整工具结果、操作凭据或服务业务正文。
- 不改变 L0～L4、目标节点批准、预授权、租约和资源所有权语义。

## Decisions

### 1. 控制面与数据面严格分离

Coordinator 只接收节点状态、Gateway endpoint、版本化工具能力摘要和脱敏服务快照。Agent
获取目录后仍通过现有 WireGuard 地址直连目标 Tool/Operation Gateway；响应正文和操作状态不
经过 Coordinator。

选择该方案是因为当前直连 Gateway 已有认证、授权、超时、大小限制和审计。让 Coordinator
代理调用会扩大秘密、可用性和容量责任，并把单点故障引入已验证的数据面。被否决的替代方案：

- **中央工具代理**：实现较快，但 Coordinator 会看到所有工具正文和操作流量。
- **模型驱动节点路由**：无法确定性处理撤销、过期和协议兼容。
- **立即自动管理 WireGuard**：会触碰用户现有网络，属于后续独立 change。

### 2. 自托管 Coordinator 使用双监听边界

Coordinator Agent API 只绑定显式配置的 WireGuard 私网地址；管理员 API 默认只绑定环回
地址。不得绑定公网、物理局域网通配地址或复用本地聊天端口。首轮使用 FastAPI 与版本化 JSON
协议，便于复用现有类型、测试和部署方式。

生产部署的 HTTPS 终止方式属于打包阶段待验证假设；A/B 开发验收可在现有 WireGuard 加密
数据面上使用 HTTP，但应用认证始终必需。MCP 不适合 enrollment、心跳和目录修订等控制协议，
因此本阶段不将其用作 Coordinator 主协议。

### 3. 一次性 enrollment token 换取 refresh 凭据和短期访问 assertion

管理员在环回 API 创建带网络、有效期和最大使用次数的一次性 token。Coordinator 只保存 token
哈希；首次注册成功后立即消耗 token，并签发只属于该节点的高熵 refresh 凭据。Agent 把
refresh 凭据保存到操作系统 keyring，配置文件只保存 Coordinator endpoint、network ID、
稳定 node ID 和固定的 Coordinator 验证公钥指纹。

节点注册请求包含本地稳定 node ID、显示名、平台、Gateway endpoint 和协议版本。相同本机身份
重试必须幂等恢复同一节点；不同身份不得占用已有 node ID。

节点使用 refresh 凭据向 Coordinator 获取短期签名访问 assertion。assertion 至少绑定
network ID、node ID、用途 audience、签发/到期时间、唯一 ID 和协议主版本；Agent 只在内存中
保留它。Tool/Operation Gateway 使用固定的 Coordinator 验证公钥离线验签，再执行本地 peer、
工具、操作和授权策略。Coordinator 的签名私钥只存在于服务端秘密存储。

首版采用标准 Ed25519 签名 JWT 或同等经过审计的标准格式，具体库在 1.x 安全 spike 固定；
不得自定义密码学协议。被否决的替代方案：

- **把逐目标 Gateway token 存入 Coordinator**：扩大中央秘密与泄漏影响面。
- **只用 Coordinator opaque token 调所有 Gateway**：Gateway 必须在线回查 Coordinator，
  把控制面故障变成数据面故障。
- **立即采用完整 mTLS PKI**：对当前 A/B 迁移和打包复杂度过高，但未来可替换 assertion。

### 4. 服务器修订号与逐节点完整快照

Coordinator 使用 SQLite 事务保存：

- network、node、credential、revocation 和 last-seen；
- capability snapshot 与 tool name/version/platform/risk/availability；
- service snapshot 与 stable service ID、协议、地址、端口、来源、置信度和 observed-at；
- 单调 server revision 和脱敏审计事件。

Agent 每类更新携带 `snapshot_id`、本地序号、生成时间和幂等键。Coordinator 对同一节点只接受
更高序号的完整快照；重复提交返回已有 revision，乱序提交拒绝。完整服务快照缺失的旧服务在
同一事务内标记 stopped，而不是等待模型推断。

选择完整快照而非首版事件流，是因为每节点数据量有明确预算，断线恢复与删除收敛更容易证明。
未来若规模需要增量事件，仍以 server revision 和周期性完整快照校正。

### 5. 新鲜度与撤销由 Coordinator 时间和状态机确定

Coordinator 在接收时写入 `received_at`，不信任 Agent 时钟决定在线状态。节点状态为：

`online → stale → offline → revoked/incompatible`

阈值由服务器配置。节点进入 stale/offline 后，其服务和能力不得表示为当前可用；撤销立即使
refresh 凭据和新 assertion 签发失效，并通过目录修订传播到 Gateway 授权缓存。已经签发的
assertion 具有很短 TTL；Gateway 在收到撤销后立即拒绝，未收到时最迟在 assertion 到期后
拒绝。客户端可以缓存最后目录用于只读展示，但必须保留 server revision、
`received_at`、freshness 和离线标记，不得把缓存升级为实时证据。

### 6. 动态工具选择采用“目录预筛选 + 短期身份 + 目标直连复核”

对指定 node ID：

1. Runtime 从本地缓存或 Coordinator 读取已授权网络内的节点摘要；
2. 排除 revoked、incompatible、offline、过期 endpoint 和不允许的能力；
3. 按任务阶段、平台、工具风险和主版本生成最小候选集合；
4. 为目标 Gateway 获取或复用有效短期 access assertion；
5. 发起直连时由 Gateway 离线验签并调用节点摘要/能力预检；
6. 目录与目标直连结果冲突时，以最新目标证据为准并记录目录陈旧。

目录只用于发现和预筛选，不授予工具或操作权限。目标 Gateway 的 peer allowlist、Tool Runtime、
Operation Policy 和本地批准仍拥有最终裁决权。

### 7. 静态 peer 采用显式迁移而非静默替换

A/B 现有 peer 配置和逐目标 Gateway token 继续工作。管理员可把一个静态 peer 导入为
Coordinator 节点候选，再在目标节点使用 enrollment token 完成身份绑定。只有 Coordinator
条目完成注册、短期身份签发、直连复核和 endpoint 匹配后，Agent 才优先使用目录解析。

Coordinator 离线时：

- 已明确配置且静态 Gateway token 有效的 static peer 仍可直连；
- Coordinator-managed peer 只有在内存中仍有未过期 assertion 时才能继续直连；
- 已验证且未超过 endpoint TTL 的目录 peer 可以尝试直连，但必须显示目录不可刷新；
- 超过 TTL、被撤销或从未直连验证的目录条目不得自动调用；
- 本地工具、资源页、操作状态、撤销、到期和恢复不受影响。

### 8. 数据最小化与可观测性

能力目录只保存工具定义摘要，不保存 schema 中可能包含的秘密示例。服务目录只保存确定性系统
元数据，不保存环境变量、命令行、业务响应正文或完整进程参数。普通审计记录 network/node、
revision、动作、结果、错误码和有界计数，不记录认证头或完整 token。

指标包括注册成功/拒绝、心跳延迟、在线状态转换、快照大小、乱序/重复数、目录查询延迟、
动态工具过滤原因和直连复核冲突。失败归因继续使用 `context`、`prompt_or_model`、
`harness_or_tool`、`governance`，Coordinator 协议与同步失败归入 `harness_or_tool`。

## Risks / Trade-offs

- [Coordinator 成为控制面单点] → 客户端有界缓存、静态 peer 回退、指数退避；不代理数据面。
- [enrollment/refresh/assertion 被窃取或重放] → enrollment 原子消费，refresh 哈希保存与轮换，
  assertion 短 TTL、audience、唯一 ID、WireGuard 传输、速率限制和不含秘密审计。
- [Coordinator 签名私钥泄漏] → 秘密存储、验证公钥指纹固定、密钥 ID 与轮换窗口；发生泄漏时
  阻断 assertion 模式并显式回退 static peer，不静默接受未知公钥。
- [被攻破节点提交伪造服务] → 节点只能更新自身快照；目录标记来源和新鲜度；目标调用仍直连
  复核，目录不授予权限。
- [Agent 时钟漂移制造“新鲜”数据] → 在线状态使用 Coordinator `received_at`；保留 Agent
  `observed_at` 仅作证据。
- [完整快照随服务数增长] → 项目级数量/字节预算、压缩留待验证；超限拒绝且保留上一修订。
- [目录与真实 Gateway 冲突] → 目标直连证据优先，记录冲突并触发下一次同步。
- [SQLite 并发写瓶颈] → 单实例、自托管、小规模目标先使用 WAL 与短事务；达到真实阈值后再评估
  外部数据库。
- [管理员撤销后客户端仍使用缓存] → 撤销使 refresh 立即失效并传播拒绝状态；assertion TTL
  限定最坏窗口，Gateway 收到撤销后立即拒绝；static peer 必须由管理员单独显式撤销。
- [错误地扩展为多租户平台] → 数据模型保留 network ID 硬隔离，但首轮没有组织、角色、计费或
  公共 endpoint；企业能力必须独立 change。

## Migration Plan

1. 先验证标准签名 assertion、协议模型、SQLite 存储和纯内存/本地 Coordinator，不连接真实 A/B。
2. 启动只绑定 B WireGuard 地址的测试 Coordinator，创建一次性 A/B enrollment token。
3. B 先注册并同步自身能力与服务，确认不修改 `HomeMac`、Gateway `8787` 和模型 `8082`。
4. A 注册并读取目录；对 B 执行“目录解析 → 短期 assertion → Gateway 验签 → 直连能力复核 →
   只读诊断”。
5. 注入 Coordinator 离线、token 重放、节点撤销、乱序快照和服务停止，验证状态收敛与回退。
6. 在稳定期保留现有静态 peer；目录路径失败时可显式切回静态配置。
7. 发布前保存 A/B 前后网络快照、目录报告、认证安全报告和清理证明。

回滚时停止 Coordinator 同步器并删除本 change 自有的本地 Coordinator 数据与凭据引用；不得
删除静态 peer、WireGuard 配置、Gateway token、操作记录或服务。重新启用静态 peer 后，现有
跨节点诊断和临时共享继续可用。

## Open Questions

- Coordinator 首个可分发形态采用独立进程还是与 B Agent 同包不同进程，需要在部署阶段比较
  故障隔离和用户操作复杂度。
- A/B 开发环境是否需要在 WireGuard 上额外配置 TLS，取决于打包与证书管理 spike；应用认证
  和禁止公网绑定不依赖该选择。
- 能力与服务完整快照的默认数量、字节预算和心跳间隔需要用现有 A/B 数据测量后固定。
- 撤销向目标 Gateway peer allowlist 的自动传播属于本 change 的应用层边界还是后续受管网络
  change，需要以首轮真机撤销体验决定；本 change 不修改 WireGuard peer。
