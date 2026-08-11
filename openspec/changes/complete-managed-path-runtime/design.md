## Context

归档 `2026-07-31-integrate-managed-node-runtime` 的任务 5.1–5.4 和 6.3 宣称 managed config 已进入治理、Provider 和路径状态，但现场代码存在清晰断点：`ManagedNetworkSynchronizer` 与 `ManagedNetworkSyncLoop` 明确只拉取、验签和保存 pending；`build_managed_network_sync_loop` 没有 Provider、治理或授权依赖；`network/path_controller.py` 只有 `PathProbe` 协议、`DirectPathVerifier` 和 `DirectPathController`，生产代码没有 `PathProbe` 实现或控制器实例。`NetworkOperationPolicy` 只在进程内保存 grant，`SQLiteNetworkGovernanceStore` 只保存执行记录，operation preauthorization 只覆盖 L2，因此仓库也没有可供 lifecycle 复用的持久 L3 授权来源。Windows/macOS 常规工厂只能暴露同步 checkpoint，不能提供真实 selection/evidence/authorization。

PR #44 和 `improve-local-product-experience` 可继续交付 Coordinator cache、overview 契约及 stale UI，但其任务 3.3 必须以本 change 的真实运行时状态为前置。`package-manual-node-runtime` 只能在合并后消费常规入口；Gateway 保持独立私网进程和监听器。当前 A/B 网络是用户已有环境，任何真实写验证都必须使用另行批准的隔离资源。

## Goals / Non-Goals

**Goals:**

- 为 Windows/macOS 建立同契约的生产只读 `PathProbe`，只读取和有界探测，不修改防火墙、WireGuard、路由或端口转发。
- 在现有网络治理 SQLite 数据库内建立唯一权威 L3 grant repository，并以单一、可恢复、单并发 lifecycle 串联同步、持久化授权读取、治理、Provider、独立验证、路径控制和脱敏状态发布。
- 保证没有精确有效的本机 L3 授权时只进入 `awaiting-authorization`，不创建授权、不生成可执行写动作、不调用 Provider apply。
- 将真实 selection/evidence/authorization/freshness 接入 Windows/macOS 常规本地入口，支持过期、刷新、降级和恢复。
- 用 fake、批准的隔离资源和证据来源标签建立递进门禁，禁止用 fake、专用脚本或历史证据替代生产完成证明。

**Non-Goals:**

- 不改变 Provider 的 plan/apply/verify/rollback/recover、所有权账本或 L3 policy 语义。
- 不修改客户防火墙、Murus、WireGuard 配置、用户路由、模型、秘密、自启动或安装包。
- 不改变 Coordinator/Gateway 协议，不把本地应用与 Gateway 合并，也不扩大 Gateway 监听范围。
- 不实现 `improve-local-product-experience` 的 React 页面、overview 聚合或 package/发布工作，不更新 FigJam 或其他外部系统。
- 不新增 relay、LAN discovery、自动 enrollment、自动授权或模型参与的网络决策。

## Decisions

### 1. 同步器保持只拉取，新增共享 managed path lifecycle

`ManagedNetworkSynchronizer` 继续只负责拉取、验签、pending/last-known-good checkpoint 与 Coordinator 退避。新 lifecycle 在它之后消费 pending，并显式持有 authorization repository、governance service、平台 Provider、`DirectPathVerifier`、`DirectPathController`、状态 repository 和 acknowledgement/path sink。这样同步故障和写入故障可以独立隔离，也避免把 Provider 副作用藏进网络客户端。

备选方案是直接把 Provider 注入 `ManagedNetworkSynchronizer`；否决原因是它会混合控制面重试与有副作用的恢复状态机，使同步重试可能隐式重放写操作。

### 2. 在现有治理 SQLite 内建立唯一权威 L3 grant repository

现有 `NetworkAuthorizationGrant` 与 `NetworkAuthorizationScope` 继续定义 L3 授权语义，但不再把进程内 `NetworkOperationPolicy` 当作持久事实来源。实现 SHALL 在 `SQLiteNetworkGovernanceStore` 使用的同一本机治理数据库内增加独立 `network_authorization_grants` 表，并通过单一 repository 管理 grant；不创建第二个授权数据库，也不从 `network_governance` 执行记录、内存 grant、signed desired config 或 operation L2 preauthorization 推断授权。

repository 的写端口只交给显式本机控制面，负责原子 approve 与 revoke；lifecycle、恢复流程和状态投影只持有只读查询端口。grant 以 `authorization_id` 为稳定身份，完整保留 network、node、revision、Provider、action、资源范围、计划摘要/观察指纹、批准时间、过期时间和撤销时间。相同 ID 不得被覆盖成不同 scope，撤销不可逆；所有时间使用 UTC。数据库缺表时只迁移为空仓库，旧执行记录和进程内 grant 不自动迁移。schema/payload 损坏、秘密字段、数据库读取失败或多条冲突记录一律 fail closed。

`NetworkOperationPolicy` SHALL 改为该 repository 上的策略门面：approve/revoke 委派给本机控制面写端口，evaluate 通过只读端口查询并精确匹配，不再保留可作为授权事实的私有内存 grant 表。这样既有治理 workflow 与新 lifecycle 共享一套策略语义和一份持久事实，重启、撤销与崩溃恢复不会在两条路径上产生不同结论。

lifecycle 只接受从该 repository 读出的精确有效授权，并要求其绑定 network、node、revision、Provider、资源范围、计划摘要/观察指纹和有效期。授权缺失、过期、撤销或不匹配时保存 pending，发布 `awaiting-authorization`，且在 Provider `apply` 前停止；崩溃恢复和 apply 前 recheck 必须重新读取同一 repository。启动、模型、对话、记忆、服务观察、Coordinator 响应和页面读取都不能持有写端口、创建或扩大授权。

备选方案一是另建授权文件或第二个 SQLite；否决原因是会产生并行事实来源、跨存储提交和恢复歧义。备选方案二是把 enrollment、signed desired config、前端确认、执行记录或内存 grant 视作授权；否决原因是这些信号没有本机 L3 资源审批语义，且在重启、撤销和并发下无法形成唯一可审计事实。

### 3. 平台 PathProbe 是只读适配器，Provider verify 仍是写事务的完成门禁

Windows/macOS `PathProbe` 通过平台只读系统接口与有界 socket 探测获得 endpoint reachability、最新 handshake、精确 host route 和 target reachability。探测目标只能来自通过策略过滤的结构化候选和 desired config；不接受 prompt、对话文本、完整秘密或任意命令。probe 不调用 Provider 写 API；Provider apply 后仍由既有 Provider `verify` 重新读取所有权和系统状态，path verifier/controller 只决定可观察 path selection，不能把命令退出码升级为 verified。

备选方案是复用通用工具运行时或模型诊断；否决原因是其输入范围更宽，且无法证明固定预算、无模型与无副作用。

### 4. selection/evidence 使用单写者持久化状态和明确新鲜度

每个 network/node 只有一个 lifecycle 写入 selection/evidence checkpoint。状态包含 schema version、revision、path type、Provider、authorization state、稳定错误、证据各维度时间、刷新时间、过期时间和来源类别，不包含 endpoint 正文、路由清单、配置正文或秘密。达到 TTL 后即使控制器最后选择为 direct，公开状态也必须降级为 stale/unverified；只有一次新的成功探测可以恢复 fresh direct。刷新请求只合并/触发只读 probe，不重放 Provider apply。

备选方案是仅在内存保存或由 Web 请求现场拼装；否决原因是重启后会丢失 provenance，且并发页面读取可能把不同时间的事实拼成伪实时状态。

### 5. 有副作用阶段保持治理状态机与崩溃恢复

在授权通过后，lifecycle 依次执行 observe → plan → policy/authorization recheck → apply → Provider verify → path verify/controller reconcile → acknowledgement。每个写事务沿用 revision/idempotency key、逐步回执、所有权账本、逆序 rollback 和 recover；授权在 apply 前再次读取，过期或撤销立即停止。崩溃恢复先检查 journal/ledger/实时状态，不盲目重放 apply。写失败、verify 失败、rollback 失败分别发布稳定状态，只有独立 verify 成功才能更新 last-known-good。

备选方案是由 path controller 直接调用 Provider；否决原因是控制器只应消费证据并选择路径，不应持有授权或资源所有权职责。

### 6. 常规入口共享装配，Gateway 与产品/package 保持依赖边界

提取 Windows/macOS 共用的 managed path 依赖工厂，由平台分支只提供只读 probe、Provider/backend 和平台能力结果。常规本地应用的 lifespan 持有唯一 lifecycle，并把真实状态 provider 交给资源 API。Gateway 不共享该 lifespan、不读取 UI 缓存、不改变监听；`improve-local-product-experience` 只消费新状态，不能反向驱动授权或写入；package change 只封装合并后的入口。

### 7. 验收采用来源分层且真实写入必须后置

第一层用纯 fake 验证状态机、授权拒绝、并发、故障矩阵和秘密边界；第二层用平台只读 probe 与受控 fixture 验证真实观察；第三层仅在明确批准的独立接口/地址/端口和隔离数据目录上验证真实 Provider 写入、回滚与恢复；第四层才可在真实 A/B 常规入口验证跨机 lifecycle。每份证据记录代码提交、平台、入口、资源批准、观测时间和来源。较低层成功、旧记录或专用脚本不得替代较高层完成条件。

## Risks / Trade-offs

- [平台只读接口在权限不足或厂商版本间不一致] → 返回稳定 `permission_denied`/`unsupported` 并只降级 path evidence；本地页面、static peer、Coordinator cache 和 Gateway 独立运行。
- [控制面 revision 与授权/观察在执行前变化] → plan 和授权绑定观察指纹，apply 前再次读取并 fail closed；不自动迁移授权。
- [授权与执行记录共享 SQLite 可能增加锁竞争或扩大数据库故障域] → 使用独立表和短事务，授权读取失败单独映射为稳定 fail-closed 错误；不把授权复制到第二个存储规避锁竞争。
- [probe 本身产生少量网络流量] → 固定候选来源、目标、超时、数量、最小刷新间隔和单并发；默认不进行任意服务扫描。
- [证据 TTL 使短暂离线更快显示 stale] → 保留 last-known-good/static 但不称为当前 direct，成功刷新后自动恢复展示。
- [跨平台工厂抽取可能触及活跃 UI change 的同一应用文件] → 本 change 先合并后由 `improve-local-product-experience` 基于该状态契约接线；同阶段应用工厂保持单一写 owner。
- [真实 Provider 测试可能影响用户网络] → 必须显式批准隔离资源、保存前后不变性证据并提供人工停止；未满足前置条件时相关任务保持未完成。

## Migration Plan

1. 先在现有治理 SQLite 中创建空的 `network_authorization_grants` 表，接入本机控制面写端口与 lifecycle 只读端口；已有数据库不迁移执行记录或内存 grant，因而升级后默认无授权并 fail closed。旧同步 checkpoint 仍可读取，但没有 path checkpoint 时公开状态为 `unconfigured`/`awaiting-authorization`，不得推断成功。
2. 增加 Windows/macOS 只读 probe 与真实观察门禁，不启用 Provider apply。
3. 在隔离 fake 和批准资源上接入治理/Provider/recover，验证 failure/rollback/manual-intervention 后再开启常规入口装配。
4. 以 feature flag 或显式 managed 配置启用新 lifecycle；失败时可回退为旧的 pull-only 同步，同时保留 pending 和 last-known-good，不删除任何用户资源。
5. 合并后由 `improve-local-product-experience` 消费真实状态完成 3.3，由 package change 在其自身门禁中封装；真实 A/B 证据只有在批准资源和常规入口均满足时生成。

## Open Questions

- Windows 与 macOS 可获得的最新 handshake/route API 及最低权限矩阵需要分别用只读 spike 固定；不可用平台能力必须显式降级，不能用命令成功或旧证据代替。
- 真实 A/B 的隔离接口名、地址、UDP 端口和批准窗口由执行前人工确认；本提案不预先占用或修改现有 `HomeMac`、B 手写配置、Gateway `8787` 或模型 `8082`。
