## ADDED Requirements

### Requirement: Overview 必须展示需要本机用户介入的操作

Overview SHALL 使用现有强类型 Operation 摘要展示需要当前本机用户立即决定、执行、确认未知结果或处理清理失败的有界队列，并 MUST 为每项提供现有操作详情链接。Overview MUST NOT 在摘要卡内直接批准、执行、撤销或重放写请求，且 Operation 列表读取失败不得阻断资源和 incident 总览。

#### Scenario: 目标节点收到待批准操作
- **WHEN** Operation 角色为 `target` 且状态为 `awaiting_authorization`
- **THEN** Overview 把它显示为“待本机批准”，用户只能先进入现有详情页复读计划和允许动作

#### Scenario: 请求节点收到已授权操作
- **WHEN** Operation 角色为 `requester` 且状态为 `authorized`
- **THEN** Overview 把它显示为“待确认执行”，且不得因远端已经授权而自动执行

#### Scenario: 写结果未知或清理失败
- **WHEN** Operation 标记提交/执行结果未知，或状态为 `cleanup_failed`
- **THEN** Overview 显示相应人工待办并链接原 Operation，不新建或自动重放另一条写请求

#### Scenario: 只有远端等待或已结束记录
- **WHEN** Operation 仅在等待远端批准，或已经成功、拒绝、取消、过期或回滚且没有清理失败
- **THEN** 它继续保留在操作页，但不冒充需要当前用户处理的 Overview 待办

#### Scenario: 操作摘要暂时不可用
- **WHEN** `/api/operations` 读取失败而资源和 incident Overview 仍可用
- **THEN** 待办卡显示独立的不可用状态，其他 Overview 内容继续展示和刷新

### Requirement: Incident 详情必须提供受限的候选操作交接

Incident 详情 SHALL 仅为已确认、目标为远端节点且当前强类型 service 快照仍能确定有效端口的 `local_only` incident 提供现有临时 HTTP 共享候选计划入口。入口 MUST 只预填 incident ID、目标节点和服务端口；点击入口不得产生写请求，且用户仍须在操作页明确确认后，由服务端重新校验合格 peer、最新只读证据、计划和目标节点授权。

#### Scenario: 已确认的远端 local-only 服务仍然新鲜
- **WHEN** incident 为 `confirmed` 的 service `local_only`，目标不是本机，且当前同一 service 在同一节点具有 `live` 或 `fresh` 的有效端口与活动状态
- **THEN** 详情提供“生成候选处理计划”入口，并在操作页预填该目标节点和端口，同时说明调查结论不是授权

#### Scenario: 用户只打开候选处理入口
- **WHEN** 用户从 incident 详情进入预填操作页但尚未勾选明确确认
- **THEN** 系统不得调用模型、创建 Operation 或向目标节点提交任何写请求

#### Scenario: Incident 当前没有安全候选动作
- **WHEN** incident 未确认、不是 `local_only` service、目标为本机、服务已停止/不可用、快照陈旧、服务不存在或端口未知
- **THEN** 详情说明当前没有可安全生成的处理入口，不猜测目标、端口或其他写操作

#### Scenario: 预填目标不再是合格 peer
- **WHEN** 用户到达操作页后，服务端返回的合格 peer 列表不再包含 incident 目标
- **THEN** 页面明确说明上下文已失效，不静默改选另一 peer 作为同一 incident 的处理目标，也不发送创建请求

#### Scenario: 用户确认生成候选计划
- **WHEN** 预填目标仍合格且用户确认目标、端口、共享端口、持续时间和副作用边界
- **THEN** 页面只调用一次现有操作创建 API，服务端重新诊断并生成无权限候选计划，后续仍进入目标节点审批、执行、验证和回滚/清理流程
