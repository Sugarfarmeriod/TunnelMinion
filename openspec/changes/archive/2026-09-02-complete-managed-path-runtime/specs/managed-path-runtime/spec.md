## ADDED Requirements

### Requirement: 平台 PathProbe 必须只读、确定且有界

Windows 与 macOS SHALL 提供生产 `PathProbe`，只从平台系统事实和经过本机策略过滤的结构化候选读取 endpoint、WireGuard handshake、唯一 peer 路由归属与 target reachability。目标 MAY 由所选 peer 的安全精确 host route 或安全网段唯一覆盖；当不存在竞争 peer 或不安全宽路由、批准的远端 target 实际连通且网络前后不变时，系统 MUST NOT 仅因缺少单独 `/32` route 判定失败。Probe MUST 拒绝本机目标，固定候选数量、目标、超时、刷新间隔和单并发，MUST NOT 调用模型、执行任意命令或修改防火墙、WireGuard、路由、端口转发和监听器。

#### Scenario: 对批准候选执行真实只读探测

- **WHEN** signed desired config 给出未过期候选且候选通过本机地址、来源和端口策略
- **THEN** 平台 probe 在固定预算内返回四个证据维度及观测时间；安全网段由所选 peer 唯一覆盖、批准的远端 target 实际连通且系统网络配置前后不变即可通过，不额外要求 `/32` route

#### Scenario: 权限不足时保存现场连通性证据

- **WHEN** 当前账户不能读取完整 WireGuard 详情，但批准的远端 target 可在固定预算内连通
- **THEN** 阶段 2.5 验收 MAY 在确认目标不是本机地址、接口与路由摘要前后不变且未执行写操作后保存 `target-connectivity` 来源证据；该证据只证明现场连通性，不得冒充生产 PathProbe 的 peer 所有权或 handshake 证据

#### Scenario: 批准目标是本机地址

- **WHEN** 批准 target 与当前接口的任一本机地址相同
- **THEN** probe 在 target 连接前 fail closed，不把本机回环式成功冒充远端 peer 连通

#### Scenario: 对话包含未批准 endpoint

- **WHEN** 模型、对话、记忆或普通工具输出包含不在结构化批准候选内的 endpoint
- **THEN** PathProbe 不探测该 endpoint，不把它加入 selection，也不调用任何网络写接口

#### Scenario: 平台只读能力不可用

- **WHEN** 当前账户无权读取 handshake/route 或平台没有受支持的只读接口
- **THEN** lifecycle 发布对应稳定降级错误，不尝试提权、sudo prompt 或写入替代路径，其他本地功能继续运行

#### Scenario: 操作者为第三层开发验收提供管理权限上下文

- **WHEN** 操作者已明确批准第三层隔离资源和真实写入窗口，并以本机交互式 `sudo`、既有 root/管理员进程或获准的 SSH 管理会话启动验收进程
- **THEN** 验收工具 MAY 在该临时权限上下文中执行批准资源上的 Provider 门禁，但 MUST NOT 接收、传输、记录或保存密码，MUST NOT 使用 `sudo -S`、修改 `sudoers`、建立持久免密凭据、安装常驻提权 helper 或新增自启动项；该权限上下文不得成为生产 lifecycle 的自行提权路径，也不得替代 Provider verify、path verify、前后不变性和精确回滚证据

### Requirement: 本机 L3 授权必须由单一权威 repository 持久化

系统 SHALL 在现有本机网络治理 SQLite 数据库内，以独立 `network_authorization_grants` 表持久化 `NetworkAuthorizationGrant`，并把它作为 L3 授权的唯一事实来源。repository MUST 提供仅限显式本机控制面的原子 approve/revoke 写端口，以及供 policy、lifecycle、恢复和状态投影使用的只读查询端口；`NetworkOperationPolicy` 的 approve/revoke/evaluate MUST 委派给这些端口，不得继续维护可作为授权事实的私有内存 grant 表。普通启动、模型、对话、记忆、服务观察、Coordinator、页面和远端输入 MUST NOT 获得写端口。系统 MUST NOT 从执行记录、内存 grant、signed desired config 或 operation L2 preauthorization 推断、迁移或扩大 L3 授权。

#### Scenario: 现有治理数据库首次升级

- **WHEN** 现有治理数据库尚无 `network_authorization_grants` 表，但包含旧执行记录或进程内曾有 grant
- **THEN** 系统只创建空授权表并视为没有授权，不从旧记录或内存推断 grant，pending 保持 `awaiting-authorization`

#### Scenario: 授权跨重启与撤销

- **WHEN** 本机控制面原子保存精确 scope 的 grant，应用重启后读取该 grant，随后本机控制面撤销它
- **THEN** 重启后的只读查询返回同一授权且撤销后不可再匹配；相同 authorization ID 不得被覆盖为不同 scope，撤销不可逆

#### Scenario: 授权存储不可证明可信

- **WHEN** 授权记录 schema/payload 损坏、包含秘密字段、出现冲突记录或数据库读取失败
- **THEN** repository fail closed 并返回稳定授权存储错误，lifecycle 不调用 Provider apply，也不回退到内存或执行记录

### Requirement: managed path 必须由单一授权治理生命周期执行

系统 SHALL 以每个 network/node 单写者 lifecycle 串联 signed config pending、权威 repository 中的本机 L3 授权、Provider observe/plan/apply/verify/rollback/recover、`DirectPathVerifier` 与 `DirectPathController`。任何 Provider 写入前 MUST 从同一 repository 重新读取并验证授权与 network、node、revision、Provider、资源范围、计划摘要/观察指纹和有效期精确匹配；普通启动、模型、对话、记忆、服务观察、Coordinator 或页面 MUST NOT 创建、扩大或代替授权。

#### Scenario: 合法 pending 没有本机授权

- **WHEN** desired config 已验签并保存为 pending，但本机没有精确有效的 L3 授权
- **THEN** lifecycle 显示 `awaiting-authorization`，不调用 Provider apply、不创建授权且不改变网络状态

#### Scenario: 授权在 apply 前过期或撤销

- **WHEN** plan 已生成但 apply 前重新读取发现授权过期、撤销或观察指纹不匹配
- **THEN** lifecycle fail closed 并保留 pending，不执行任何写步骤，也不把旧批准迁移到新 revision

#### Scenario: 已授权 revision 完成独立验证

- **WHEN** 精确授权有效，Provider apply 返回逐步回执且 Provider verify 与 path verify 均基于重新读取的实时事实成功
- **THEN** lifecycle 才更新 verified、selection 和 last-known-good，并发送对应脱敏 acknowledgement/path status

### Requirement: path selection 与 evidence 必须持久化来源和新鲜度

系统 MUST 持久化版本化、脱敏的 path selection/evidence，至少包含 network/node 关联、revision、Provider、path type、authorization state、稳定错误、各证据时间、刷新时间、过期时间和来源类别。状态 MUST NOT 包含完整 endpoint、用户路由清单、配置正文、token、refresh、私钥或预共享密钥。超过证据 TTL 后 MUST 显示 stale/unverified；只读刷新成功后才能恢复 fresh direct，刷新 MUST NOT 重放 Provider apply。

#### Scenario: direct 证据过期

- **WHEN** 上次 selection 为 direct 但当前时间超过证据 TTL 且尚未取得新证据
- **THEN** 常规入口保留 last-known-good 参考但把当前 path 标记为 stale/unverified，不宣称 peer 当前可达

#### Scenario: 只读刷新恢复

- **WHEN** 陈旧状态触发合并后的单次刷新且新的 handshake、唯一 peer 路由归属和远端 target probe 全部成功
- **THEN** 系统以新观测时间更新 selection/evidence 为 fresh direct，且没有调用 Provider apply

#### Scenario: 读取或导出 path 状态

- **WHEN** 本地资源 API、诊断导出或 Coordinator path sink 读取状态
- **THEN** 输出包含来源、新鲜度、revision 和稳定错误而不包含任何可重放秘密、完整 endpoint 或用户路由

### Requirement: 生命周期故障必须隔离并可恢复

同步、授权读取、Provider、probe、controller、状态持久化和远端上报 SHALL 是可区分的故障域。失败 MUST 保留可证明的 pending、last-known-good、static path 和逐步回执；崩溃恢复 MUST 先核对授权、journal、所有权账本和实时系统状态，不得盲目重放 apply 或清理未知资源。只有独立验证成功才能覆盖 last-known-good。

#### Scenario: probe 失败但 Provider 状态稳定

- **WHEN** Provider 已验证的资源仍匹配所有权，但本轮 target probe 超时
- **THEN** controller 按阈值降级 selection 并保留 last-known-good，且不自动删除、重建或改写受管资源

#### Scenario: apply 后进程崩溃

- **WHEN** 重启发现未完成 Provider journal 或 applying 状态
- **THEN** recover 先重新读取授权、所有权和实时状态，再幂等完成验证或回滚；无法证明所有权时进入 `manual_intervention`

#### Scenario: Coordinator 与模型同时离线

- **WHEN** 控制面和模型 Provider 均不可用但本机 checkpoint、授权与只读平台能力可用
- **THEN** 本机 path freshness/selection、恢复和 static 降级继续工作，Gateway 与本地只读功能不因该故障停止

### Requirement: 安全诊断预览必须来自常规入口且不得冒充真实写入

本 change 的完成证据 MUST 来自 Windows/macOS 常规应用工厂、隔离数据目录和无网络写入的诊断状态读取，并记录代码提交、平台、入口、来源和观测时间。该证据 MUST 证明未配置、待授权、过期和平台能力降级被如实表达，且 MUST NOT 被标记为真实 Provider、真实 path 或跨机 A/B 完成。真实 Provider 写入与跨机 A/B SHALL 由未来独立 change 重新授权和验收。

#### Scenario: fake lifecycle 全部通过

- **WHEN** fake Provider 覆盖授权拒绝、apply、verify failure、rollback failure、崩溃恢复和故障隔离
- **THEN** 系统只证明状态机门禁通过，不把结果声明为真实 Provider 或跨机 A/B 完成

#### Scenario: 常规入口处于干净未配置状态

- **WHEN** Windows 或 macOS 常规应用工厂使用新的隔离数据目录启动且没有 enrollment、managed config 或 L3 授权
- **THEN** 资源 API 如实返回 unconfigured/runtime-absent/path-absent 诊断状态，不调用 Provider apply 且不修改网络

#### Scenario: 真实执行尚未另行授权

- **WHEN** 当前 change 没有未来真实执行 change 的明确授权、资源和退出条件
- **THEN** 验收停止在 diagnostic-preview，不创建提权请求、真实写入窗口或跨机 A/B，并保持依赖真实 path 证据的下游任务未解锁
