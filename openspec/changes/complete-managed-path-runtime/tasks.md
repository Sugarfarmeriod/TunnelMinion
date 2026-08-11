## 0. 基线、归属与安全前置

- [x] 0.1 从实现开始时最新 `origin/main` 创建/更新匹配的 `feature/complete-managed-path-runtime` 分支，确认工作树干净、基线已包含本提案且全程不读取或修改 `docs/questions/`
  - 证据：2026-08-10 将干净分支以 `--ff-only` 从 `369c9b3` 快进到 `origin/main@5f00e073`；基线即合并提案的 PR #47，全程搜索均显式排除禁止目录。
- [x] 0.2 固定单一主写 owner 负责公共 lifecycle、应用工厂、状态 schema 和本 change 的 OpenSpec tasks；记录与 `improve-local-product-experience` 应用工厂写入的串行合并顺序
  - 归属：本任务是阶段 0–1 的唯一 OpenSpec tasks 与 `src/tunnelminion/network/**` 主写者；阶段 1 不修改应用工厂。未来应用工厂接线必须先合并本 change 的状态契约，再由 `improve-local-product-experience` owner 串行 rebase/接线，禁止同阶段并写 `app.py`/`macos_app.py`。
- [x] 0.3 只读盘点现有 L3 authorization/policy repository、Provider/governance/ledger/journal、sync checkpoint 和 path controller 接口，产出 network/node/revision/Provider/资源/计划摘要/观察指纹/有效期字段映射
  - 授权映射：`NetworkAuthorizationScope` 已绑定 network/node/provider/action、ownership resource/fingerprint、接口/地址池/host route/重叠路由/listen port/peer/relay、revision/parent revision 与 `plan_hash`；`NetworkAuthorizationGrant` 已绑定批准/过期/撤销时间并提供 `is_active`。
  - 持久化缺口与决策：`NetworkOperationPolicy` 仅保存进程内 grant；`SQLiteNetworkGovernanceStore` 保存执行记录而不保存授权；operation preauthorization 仅覆盖 L2。因此在现有网络治理 SQLite 内新增独立 `network_authorization_grants` 表和单一 repository，作为唯一 L3 授权事实来源；不新建第二个授权数据库，不从执行记录、内存 grant、signed config 或 L2 preauthorization 推断授权。
  - 执行映射：`NetworkProvider` 固定 observe/plan/apply/verify/rollback/recover；ledger 以 network/node 保存 provider、resource/stable interface、creation nonce、public key hash、parent revision、desired hash、system fingerprint；平台 journal 以幂等键保存逐步回执。
  - 同步/路径映射：sync checkpoint 保存 pending/applied/last-known-good revision 与退避；path verifier/controller 已包含 provider/revision、候选哈希、handshake/route/target 时间维度、阈值与 last-known-good，但没有生产 probe、授权 repository 或 path checkpoint。
- [x] 0.4 固定 Windows/macOS 只读 handshake/route/probe 能力、最低权限、稳定错误、TTL、超时、候选数量和刷新间隔矩阵；未验证能力标记为 spike 假设
  - 已证实仓库能力：两端 `SystemReader` 只提供接口、监听器与进程读取；macOS 仅对监听器增加固定 `lsof` 降级。仓库没有生产 `PathProbe`、handshake reader 或精确 route reader，故这些平台能力与最低权限均标记为阶段 2 spike 假设，本轮绝不现场探测。
  - 固定契约基线：候选上限 4、单候选 1s、target 2s、handshake 最大年龄 180s、连续失败/成功阈值 3/2、minimum dwell 30s；阶段 2 待验证假设为 evidence TTL 180s、最小刷新间隔 30s、只读权限不足映射 `permission_denied`、能力缺失映射 `unsupported`，不得用命令成功或旧证据替代。
  - 稳定失败维度沿用 `no_approved_candidate`、`endpoint_unreachable`、`handshake_stale`、`host_route_missing`、`target_unreachable`；平台实现、权限与真实延迟在阶段 2 验证前均不宣称成立。
- [x] 0.5 固定禁止修改清单与前后不变性采集：`HomeMac`、B 手写配置、客户防火墙/Murus、WireGuard、用户路由、Gateway `8787`、模型 `8082`、秘密和自启动
  - 本轮禁止调用任何真实 probe/Provider/平台写接口；禁止修改或读取客户网络正文。后续真实门禁必须分别采集接口/路由/listener/配置摘要的前后不变性，并保持 `HomeMac`、B 手写配置、防火墙/Murus、WireGuard、用户路由、Gateway `8787`、模型 `8082`、秘密存储和自启动完全不变。

## 1. 状态、授权端口与纯 fake 安全骨架

- [x] 1.1 定义版本化脱敏 selection/evidence/authorization/freshness 状态、稳定错误和来源类别，拒绝 endpoint 正文、路由清单、desired config、token、refresh、私钥与预共享密钥
- [x] 1.2 实现单写者 path checkpoint repository 的原子保存、兼容读取、损坏 fail-closed 和零秘密扫描；旧数据缺少 path 状态时不得推断 direct
  - 证据：代码 HEAD `17a44c5` 将 owner/lock/load/secret scan/temp/replace/fsync 绑定可信目录句柄，移除路径型 SQLite 锁，并覆盖跨实例/进程 lease、真实 symlink/reparse、确定性目录替换 race、损坏恢复与元数据失败；远端 run `31336268697` 的 macOS job `93302528091`、Windows job `93302528124` 均全绿。
- [x] 1.3 在现有网络治理 SQLite 内实现唯一权威 L3 grant repository：独立授权表、本机控制面原子 approve/revoke、policy/lifecycle 只读查询、空库迁移、重启恢复、不可逆撤销、损坏/冲突/秘密/读取失败 fail-closed；将 `NetworkOperationPolicy` 改为 repository 策略门面并复用现有精确匹配器，覆盖缺失、过期、撤销、revision/Provider/资源/摘要/指纹不匹配
  - 规划约束：不得新建第二个授权数据库或并行事实来源；不得从 `network_governance` 执行记录、进程内 grant、signed desired config 或 operation L2 preauthorization 推断/迁移 L3 授权；普通消费者不得获得 repository 写端口。
- [x] 1.4 用只读 fake probe、fake Provider 和 fake sinks 建立 lifecycle 骨架，证明无授权只保存 pending/显示 `awaiting-authorization` 且 Provider apply 调用数为零
- [x] 1.5 覆盖启动、模型、对话、记忆、服务观察、Coordinator 和页面读取不能创建/扩大授权，刷新只合并只读 probe 且不重放 apply
  - 证据：可执行架构测试实际启动 FastAPI lifespan，并读取模型配置、对话、记忆、服务观察、managed node、Coordinator、network-path 与资源页面；L3 `approve`/`revoke` 和平台 Provider `apply` 均由一旦调用即失败的 trap 保护且调用数为零。阶段一 lifecycle 的并发 refresh 测试继续证明请求只合并到单次只读 refresher、候选 evidence 不提交且 Provider 调用数为零；不再使用消费者字符串清单或源码搜索替代运行证据。
- [x] 1.6 运行状态 schema、授权 repository/门禁、迁移、重启、并发、损坏、秘密扫描、格式、类型和分支覆盖门禁；检查 diff 后以独立 Conventional Commit 提交并普通 push 本阶段
  - 当前证据：Ruff format/check、Pyright strict、全量 `856 passed, 5 skipped`（`14,411` statements / `2,838` branches = 100%）、授权仓储迁移/重启/撤销不可逆/并发冲突/损坏/秘密与读取失败定向覆盖、`openspec validate complete-managed-path-runtime --strict` 均通过；本阶段未触碰 `docs/questions/`、平台探针、应用工厂、CI 或 Provider 写入。

## 2. Windows/macOS 生产只读 PathProbe

- [x] 2.1 先用受控 fixture 固定 `PathProbe` 共用契约：候选来源/网段/端口过滤、单并发、超时、取消、最小刷新间隔和四维证据时间
  - 证据：`src/tunnelminion/network/path_probe.py` 固定候选上限 4、单候选 1s、target 2s、最小刷新 30s、单并发锁、取消传播和 endpoint/handshake/host-route/target 四维时间；`tests/network/test_path_probe.py` 以受控 fixture 覆盖契约。
- [x] 2.2 实现 Windows 只读 endpoint/handshake/精确 host route/target probe 适配，权限不足或工具缺失只返回稳定降级且不提权、不执行任意命令
  - 证据：`WindowsPathProbe` 仅消费固定参数的 `wg show` 与 `route.exe print` 只读观察器，支持 IPv4/IPv6 精确 host route，并将权限拒绝、能力缺失和读取失败稳定映射；平台定向测试覆盖成功、IPv6、权限/依赖/读取失败和缺失候选。
- [x] 2.3 实现 macOS 同契约只读适配，明确官方/受支持读取边界，不调用 Murus、防火墙写接口、route 写命令或 WireGuard 配置命令
  - 证据：`MacOSPathProbe` 仅消费固定参数的 `wg show` 与 `netstat -rn -f inet|inet6` 只读观察器，覆盖双地址族精确 host route，稳定降级且不含 Murus、防火墙、route 写入或 WireGuard 配置调用；平台定向测试覆盖相同失败边界。
- [x] 2.4 覆盖恶意/过期/超预算候选、对话 endpoint、IPv4/IPv6、旧 handshake、route 缺失、target timeout、权限拒绝和取消矩阵
  - 证据：网络 fixture 覆盖恶意/对话来源、批准网段和端口过滤、过期与超预算候选、IPv4/IPv6 endpoint、旧 handshake、精确 route 缺失、target 超时、权限/unsupported、取消、缓存刷新和并发；Windows/macOS fixture 另覆盖平台错误映射。
- [ ] 2.5 在 Windows/macOS 只读环境保存探测前后网络不变性与来源证据；无法现场验证的平台保持对应真实门禁未完成，不用 fixture 代替
  - 现场门禁未完成：当前执行环境未同时提供可批准的 Windows/macOS 隔离资源与现场验证条件；本阶段未调用真实 PathProbe 或客户网络接口，受控 fixture 未被当作生产能力或现场证据。
- [ ] 2.6 运行跨平台 probe 契约、架构无模型/无写入扫描、格式、类型和分支覆盖门禁；检查 diff 后以独立 Conventional Commit 提交并普通 push 本阶段
  - 质量门禁已执行并通过，但本任务按要求保持未完成：2.5 的双平台真实只读前后不变性与来源证据缺失，因此不将本地测试、fixture 或代码门禁外推为阶段完成。

## 3. fake Provider 下的完整治理生命周期

- [ ] 3.1 将 synchronizer 保持为 pull/verify/pending 组件，新增共享 lifecycle 串联 authorization → observe → plan → recheck → apply → Provider verify → path verify/controller → sinks
- [ ] 3.2 为 lifecycle 固定 revision/idempotency key、单并发、取消安全点、逐步回执、last-known-good 更新条件和 acknowledgement/path status 顺序
- [ ] 3.3 用隔离 fake 覆盖授权成功、apply success、Provider verify failure、path verify failure、部分 apply、rollback failure、ownership conflict 和 `manual_intervention`
- [ ] 3.4 覆盖崩溃发生在 plan/apply/verify/ack 各边界时的恢复，证明先核对授权、journal、ledger 和实时状态且不盲目重放 apply
- [ ] 3.5 覆盖 sync、authorization、Provider、probe、controller、checkpoint 与 sink 独立失败，证明 pending/last-known-good/static、本地只读功能和 Gateway 边界不受连带破坏
- [ ] 3.6 运行治理、Provider 合约、所有权、恢复、并发、秘密、格式、类型和分支覆盖门禁；明确 fake 仅证明状态机后，以独立 Conventional Commit 提交并普通 push 本阶段

## 4. 证据 TTL、刷新与真实状态投影

- [ ] 4.1 将 `DirectPathVerifier`/`DirectPathController` 接入持久化状态，固定 direct 成功窗口、失败阈值、minimum dwell、fallback 和 rollback callback 边界
- [ ] 4.2 实现 evidence TTL：过期后公开状态降为 stale/unverified 并保留 last-known-good 参考，只有新一轮成功只读 probe 才恢复 fresh direct
- [ ] 4.3 实现刷新合并、并发抑制、取消和速率预算，证明 GET/refresh 不触发 Provider plan/apply、不延长旧证据时间
- [ ] 4.4 让公开状态和 sinks 输出真实 selection/evidence/authorization/source/freshness/revision/stable error，并统一脱敏完整 endpoint、路由和秘密
- [ ] 4.5 覆盖时钟边界、进程重启、checkpoint 损坏、旧 schema、刷新失败后旧缓存、上报失败后本地状态和零秘密导出
- [ ] 4.6 运行 controller、freshness、资源状态、恢复、秘密、格式、类型和分支覆盖门禁；检查 diff 后以独立 Conventional Commit 提交并普通 push 本阶段

## 5. Windows/macOS 常规应用单一装配

- [ ] 5.1 抽取 Windows/macOS 共用 managed path 依赖工厂，只让平台层提供 probe、Provider/backend 与能力状态，避免两端产生不同语义
- [ ] 5.2 在常规本地应用 lifespan 中托管唯一 lifecycle，未配置/enrollment-required/awaiting-authorization 时保持零写入且不改变环回绑定
- [ ] 5.3 将真实 lifecycle 状态接入现有资源 API provider，覆盖 configured 不再误报 `unconfigured`、过期不误报 fresh、授权缺失不误报 applied
- [ ] 5.4 增加架构边界测试，证明 Gateway 仍是独立私网进程/监听器、不共享本机 lifecycle，模型、对话和 `improve-local-product-experience` 消费端不能反向驱动写入
- [ ] 5.5 覆盖 Windows/macOS 常规入口的未配置、凭据缺失、无模型、Coordinator 离线、probe 降级、重启和停止安全点矩阵
- [ ] 5.6 运行双平台应用、Web 契约、Gateway 监听边界、无模型、全量 Python 和 OpenSpec strict 门禁；检查 diff 后以独立 Conventional Commit 提交并普通 push 本阶段

## 6. 批准资源上的真实 Provider 门禁

- [ ] 6.1 在执行任何真实写入前记录人工批准的独立接口、地址、host route、UDP 端口、数据目录、L3 授权有效期、停止方式和前后不变性基线；任一缺失则本阶段保持未完成
- [ ] 6.2 先在单平台批准资源上用常规 lifecycle 验证 observe/plan 预览与 authorization recheck，人工核对计划不包含客户防火墙、Murus、已有 WireGuard、用户宽路由或未知资源
- [ ] 6.3 在批准资源上验证真实 apply → Provider verify → path verify → selection → acknowledgement，并保存提交、平台、入口、授权和观测时间 provenance
- [ ] 6.4 注入真实 verify failure/受控中断并验证 rollback/recover、所有权冲突和 manual intervention，不用命令退出码或 fake 证据替代
- [ ] 6.5 在另一平台重复相同门禁；若平台资源或权限未获批准，只报告 blocker，不将单平台结果外推为双平台完成
- [ ] 6.6 核对 `HomeMac`、B 手写配置、客户防火墙/Murus、WireGuard、用户路由、Gateway `8787`、模型 `8082`、秘密和自启动前后不变；检查证据与 diff 后以独立 Conventional Commit 提交并普通 push 本阶段

## 7. 常规入口真实 A/B 与下游交接

- [ ] 7.1 只有阶段 1–6 门禁和双端隔离资源批准完成后，才用 Windows/macOS 常规入口执行真实 A/B authorization → lifecycle → selection/evidence → TTL stale → refresh recovery
- [ ] 7.2 覆盖 Coordinator 离线、模型缺失、单端 probe 失败、sink 失败、重启恢复和 static fallback；证明本地只读功能与独立 Gateway 继续工作
- [ ] 7.3 保存 A/B 证据 provenance 与前后不变性；专用脚本、旧归档证据、fake、PR #44 Coordinator/cache 或 stale UI 均不得替代本轮常规入口结果
- [ ] 7.4 向 `improve-local-product-experience` 明确交付真实 status provider/schema 作为其 3.3 前置，不修改其前端、package、FigJam 或 tasks；向 package change 只交付已合并常规入口能力
- [ ] 7.5 运行全量质量、架构、安全、秘密、双平台真实门禁和 `openspec validate complete-managed-path-runtime --strict`，核对所有证据来自当前提交且未把降级成功计为生产成功
- [ ] 7.6 检查最终 `git status`/diff/生成物/秘密与任务勾选范围，以 Conventional Commit 提交并普通 push，创建面向 `main` 的 Draft PR；合并后再同步主规格和归档 change
