## Context

主干已经具备两条独立且通过验收的路径：Overview 能展示 incident、公开调查轨迹和上下文追问；操作页能生成最新候选计划、请求目标节点批准、执行、验证、访问与清理。当前缺口只在产品编排层：incident 详情没有进入候选计划的入口，Overview 也没有显示等待本机用户处理的 Operation。

本阶段不需要新的领域模型或写接口。incident 快照已有稳定 `service_id`、`target_node_id`、端口、来源和新鲜度；操作页已有强类型 peer 列表和受控表单；`/api/operations` 已同时返回 requester/target 摘要。最小完整方案是用这些现有只读契约完成前端交接，并把所有副作用继续留在已审计的操作 API 后面。

## Goals / Non-Goals

**Goals:**

- 默认 Overview 明确显示真正需要本机用户介入的 Operation，并能打开最新详情。
- 已确认的远端 `local_only` 服务 incident 在当前快照仍有可信端口时，可进入预填的临时 HTTP 共享候选计划表单。
- 用户点击处理入口时不产生写请求；只有再次明确确认表单后才向现有 API 提交一次。
- 预填、peer 变化、接口失败和不可处理 incident 都采用确定性说明，不猜测目标或降级为自动执行。
- 用 React 与隔离 Playwright 证明 Incident → 候选计划表单 → 待审批 Operation 的组合路径。

**Non-Goals:**

- 不新增通用 remediation/Playbook 框架、incident 专用写接口、Operation 类型或自动关闭 incident。
- 不把 incident 报告、模型结论、URL 参数或历史快照当作授权和可执行证据。
- 不持久化新的 incident-operation 外键；本阶段的审计权威仍是最新诊断生成的 OperationPlan。
- 不增加 Linux、relay、Provider、自动组网、服务重启、Docker 控制、WireGuard、防火墙、路由或 DNS 写入。
- 不修改模型配置，不接收或迁移 DeepSeek 等 Provider 的秘密。

## Decisions

### 1. 用现有页面与 API 完成交接，不新增后端写路径

Incident 详情只生成到 `/app/operations` 的本地导航，携带 `incident_id`、`target_node_id` 和 `service_port` 作为不可信预填参数。导航本身不调用模型、不创建 Operation；操作页仍通过现有表单收集共享端口、时长和明确确认，再调用现有 `POST /api/operations`。

被否决的方案：新增 `POST /api/incidents/{id}/remediate`。它会复制现有表单、错误语义和写结果未知处理，并制造第二条较难审计的创建路径。

### 2. 只对当前可证明可交接的 incident 展示入口

前端只在以下条件全部满足时显示候选处理入口：incident 为 `confirmed`；事件为 `local_only` 且对象为 service；Overview 能唯一识别本机节点，事件目标不是本机；当前 service 列表仍包含同一 `service_id` 和 `node_id`；端口存在；service 状态不是 `unavailable`/`stopped`，生命周期不是 `stopped`，新鲜度为 `live` 或 `fresh`。其余情况显示本阶段没有安全候选动作的原因。

这只是是否提供便捷入口的显示规则，不是执行判定。现有请求服务仍重新解析合格 peer、采集最新只读诊断，并要求唯一的远端 loopback HTTP 证据后才生成候选计划。

被否决的方案：让模型根据 conclusion 自由决定 remediation。公开结论是说明文本，不是受信任参数，也不能扩大现有唯一写能力。

### 3. 操作页验证预填上下文且不静默改目标

操作页仅接受符合 NodeId 格式和 1–65535 范围的预填值。peer 列表加载后，只有目标仍在服务端返回的合格集合中才自动选中；否则页面明确提示 incident 目标当前不合格，并保持普通新建入口与 incident 请求分离，不会静默换成第一个 peer 冒充同一处理请求。

`incident_id` 只用于页面说明和返回 Overview 的链接，不发送到操作创建 API，不影响候选计划、幂等键或授权。

### 4. Overview 待办由现有 Operation 摘要确定性投影

Overview 使用现有 `listOperations()` React Query 缓存独立读取操作摘要，只显示：目标端 `awaiting_authorization`、请求端 `authorized`、任一写结果未知、以及 `cleanup_failed`。远端尚未批准、已成功但无需处理、已拒绝或已结束记录仍留在操作页，不冒充“待你处理”。

操作 API 失败时只把待办卡标为不可用，不影响资源与 incident 总览。卡片只提供详情链接；批准、拒绝、执行或撤销仍必须在详情页复读最新状态。

被否决的方案：扩展 `resource-overview/v1`。操作本身已有独立强类型 API，重复聚合会要求无必要的契约版本迁移并产生两个状态来源。

### 5. 组合验收只使用隔离 HTTP fixture

React 单元测试覆盖显示规则、预填校验、无自动 POST 和待办过滤；Playwright 用 mock HTTP 响应走通远端 `local_only` incident、预填表单、一次创建和 Operation 详情。正式包验收确认默认 Overview 能看到既有目标端待审批记录。所有测试不得调用真实模型、Gateway、网络写入或生产端口。

## Risks / Trade-offs

- [Overview 的 incident 与 operation 查询时间不同] → 两张卡分别显示各自状态；任何动作都在详情页重新读取，Overview 不声称原子快照。
- [URL 预填值被修改] → 只作为表单默认值；服务端继续校验 peer、最新诊断、计划和授权，前端不增加可信度。
- [incident 发生后服务状态变化] → 新鲜度/状态显示规则会隐藏快捷入口；即使页面已打开，现有候选计划生成仍会因最新证据不匹配而拒绝。
- [当前节点自己的 local-only incident 无法由同一节点发起远端请求] → 详情明确说明当前没有安全处理入口；不伪造 self-peer 或新增本机写能力。
- [没有持久化 incident-operation 关系] → 用户路径和操作审计完整，但无法按 incident 做长期操作统计；只有真实需求出现一对多处理或自动关闭 incident 时再增加稳定关联。

## Migration Plan

1. 先增加纯前端投影与单元测试，不变更数据库、API 或协议。
2. 增加隔离组合浏览器验收和正式包 Overview 待办断言。
3. 运行现有 Python/React/Playwright/OpenSpec 门禁，再串行运行一次现有 Qwen 候选计划主路径评测；重复内存不足才按既定规则降级到 DeepSeek V4 Flash。
4. 回滚只需撤销前端入口与卡片；已有 incident、Operation 和租约生命周期不受影响。

## Deferred Observations

- `README.md` 仍使用较早的 MVP/下一阶段措辞，待主线功能冻结后做一次独立文档校准，不混入本阶段。
- incident 与 Operation 暂无持久化关联；只有需要跨会话因果统计、一个 incident 多种操作或自动关闭时再立独立需求。
- Linux Observer 与真机 incident 验收尚未完成，投递口径继续只写 Windows/macOS；本阶段不为简历措辞恢复 Linux 工作。

## Open Questions

无阻断性问题。当前唯一安全处理类型仍是已实现的远端本机 HTTP 临时共享；更多处理类型必须由真实用户需求和独立安全规格触发。
