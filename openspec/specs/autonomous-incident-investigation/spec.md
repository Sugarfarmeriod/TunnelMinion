# autonomous-incident-investigation Specification

## Purpose

规定模型外的确定性状态快照与 incident 触发、单 Investigation Agent 的只读调查循环、证据化停止条件、持久化恢复和操作审批边界。

## Requirements

### Requirement: Runtime 必须生成有界且可比较的状态快照

Runtime SHALL 在模型外从现有节点摘要、WireGuard、监听端口、进程、Docker、服务可达性和 Coordinator 服务目录生成规范化状态快照。快照 MUST 包含稳定对象身份、状态、来源、新鲜度、观测时间和修订，MUST 排除秘密、业务响应正文和无界原始工具结果。

#### Scenario: 正常后台刷新

- **WHEN** 后台观察周期到达且节点与服务状态未变化
- **THEN** Runtime 生成并保存有界快照，不调用模型、不创建 incident，也不改变系统状态

#### Scenario: 目录状态已经陈旧

- **WHEN** Coordinator 缓存超过规定 TTL
- **THEN** 快照把相关节点与服务标记为 stale 并保留最后有效证据时间，不把缓存记录为当前在线事实

### Requirement: 快照差异必须确定性地产生并去重 incident

比较器 MUST 只根据规范化快照和固定规则识别服务新增、服务消失、节点离线、状态陈旧、仅本机可用和远端不可达事件。相同对象、事件类型和基线修订 MUST 生成稳定去重键；重复观察 MUST NOT 重复启动调查。

#### Scenario: 新监听服务稳定出现

- **WHEN** 当前快照相对已接受基线新增一个满足确认窗口的服务
- **THEN** 系统创建一个 `service_added` incident，并关联前后快照和差异证据

#### Scenario: 同一异常连续刷新

- **WHEN** 后续快照仍包含相同的远端不可达状态且没有新的基线修订
- **THEN** 系统更新该 incident 的最后观测时间，不创建重复 incident 或第二个调查 run

#### Scenario: 短暂抖动未达到确认规则

- **WHEN** 一个变化在固定确认窗口内恢复且未达到触发条件
- **THEN** 系统记录观察结果但不创建 incident、不调用模型

### Requirement: 只有满足触发规则的 incident 才能启动单 Investigation Agent

系统 SHALL 仅为满足严重度、确认和去重规则的 incident 启动 Investigation Agent。每个 incident 同时最多存在一个调查 run；正常刷新、已抑制事件和重复事件 MUST NOT 调用模型。

#### Scenario: 重要服务从目录消失

- **WHEN** 已确认活动的服务在完整新快照中消失并满足触发规则
- **THEN** 系统创建 incident 并启动唯一一个调查 run

#### Scenario: 模型 Provider 不可用

- **WHEN** incident 满足触发规则但模型健康检查失败
- **THEN** incident 标记为 `investigation_unavailable`，保留确定性差异证据且总览继续工作，不自动重试或丢失事件

### Requirement: Investigation Agent 必须维护公开的候选假设状态

每个调查 run MUST 保存候选根因、每项 `candidate`、`supported`、`rejected` 或 `unknown` 状态、支持或反驳证据引用、已执行工具和剩余预算。系统 MUST NOT 保存或展示隐藏思维链。

#### Scenario: 监听证据淘汰防火墙假设

- **WHEN** 工具确认服务仅监听远端 `127.0.0.1` 且跨节点探测失败
- **THEN** Agent 将“仅本机监听”标记为 supported，更新或淘汰冲突假设，并引用监听与探测证据

#### Scenario: 证据互相冲突

- **WHEN** 两项仍有效的工具证据对同一候选根因给出冲突结果
- **THEN** Agent 保持该根因为 candidate 或 unknown，公开记录冲突且不得将其标记为确认结论

### Requirement: Agent 只能动态选择既有只读工具

Investigation Agent SHALL 只能从当前策略、平台、节点状态和任务阶段允许的 `get_node_summary`、`get_wireguard_status`、`list_network_listeners`、`get_process_summary`、`list_docker_services`、`probe_service_reachability` 中选择工具。所有参数 MUST 由 Tool Runtime 校验；系统 MUST NOT 提供 Shell、Python、未知工具或任何写操作。当前节点的本机工具 MUST 只向 `local_observation` 来源的 incident 暴露和执行。对于该来源的 `service_added`，模型首轮 MUST 只获得 `list_network_listeners`，后续 MUST 只获得该工具与 `get_process_summary`；如果模型首轮没有选择工具，Runtime MUST 通过同一 Tool Runtime 执行一次 `list_network_listeners` 后再继续模型循环。该规则 MUST 同时覆盖结构有效和结构无效的首轮无工具响应，且 MUST NOT 应用于远端、Coordinator 目录或聚合来源。

#### Scenario: Agent 需要区分进程退出与端口映射变化

- **WHEN** 当前证据不足且进程摘要与 Docker 服务工具均可用
- **THEN** Agent 选择填补证据缺口所需的工具，Runtime 记录候选、选择和排除原因

#### Scenario: 模型请求执行未知命令

- **WHEN** 模型请求 Shell、Python 或注册表外工具
- **THEN** Runtime 拒绝请求、不执行系统调用，并将该步骤记录为调查失败证据

#### Scenario: 本机服务首轮返回合法无工具报告

- **WHEN** `local_observation` 来源的服务 incident 首轮要求工具，但模型返回结构有效且没有工具调用的证据不足报告
- **THEN** Runtime 忽略该轮提前停止意图，通过既有 Tool Runtime 执行一次 `list_network_listeners`，并把真实结果交回下一轮模型判断

#### Scenario: 本机新增服务只能选择场景相关工具

- **WHEN** `local_observation` 来源的 `service_added` 进入调查循环
- **THEN** 首轮只暴露 `list_network_listeners`，完成一次监听尝试后的轮次只暴露该工具与 `get_process_summary`，且不暴露节点、WireGuard、Docker 或可达性工具

#### Scenario: 后续工具调用与终态 Schema 同时启用

- **WHEN** 已取得一次监听证据的后续轮次携带调查终态 JSON Schema，模型返回 `content=null` 和一个允许的工具调用
- **THEN** Provider 先保留工具调用并交给 Tool Runtime 执行，只在没有工具调用时解析结构化终态正文

#### Scenario: 本机服务首轮返回无效无工具响应

- **WHEN** `local_observation` 来源的服务 incident 首轮既没有工具调用也没有合法调查结构
- **THEN** Runtime 通过既有 Tool Runtime 执行一次 `list_network_listeners`，且仍受平台策略、参数校验、调用预算和审计约束

#### Scenario: 远端来源首轮没有工具调用

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 首轮没有工具调用
- **THEN** Runtime 不执行任何本机兜底工具，合法证据不足报告可以保留，无效响应按现有失败路径结束

#### Scenario: 远端来源主动请求本机工具

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 中，模型主动请求当前节点的监听、进程或其他本机工具
- **THEN** Runtime 不向该请求暴露或执行本机工具，也不把当前节点的工具结果记录为远端对象证据

### Requirement: 调查必须在明确停止条件下生成证据化报告

Runtime MUST 对模型轮次、工具调用数、墙钟时间和上下文使用设置上限，并在根因证据充分、必要信息不可获得、预算耗尽、用户取消或运行失败时停止。报告 SHALL 区分已确认事实、候选解释、未知项、停止原因和证据引用；没有有效证据的断言 MUST NOT 成为确认结论。

#### Scenario: 根因证据充分

- **WHEN** 一个候选根因满足固定证据门槛且不存在冲突关键证据
- **THEN** Agent 停止额外调用并生成引用对应 tool run 的结论

#### Scenario: 调用预算耗尽

- **WHEN** 调查达到最大工具调用数但仍无法确认根因
- **THEN** Runtime 停止后续调用，报告已有事实、未知项和 `budget_exhausted` 停止原因

#### Scenario: 必要工具不可用

- **WHEN** 判断根因所需的远端工具因节点离线或权限不足不可用
- **THEN** 调查以 `insufficient_evidence` 结束，不用模型常识补写实时事实

### Requirement: Incident 与调查状态必须持久化并安全恢复

系统 SHALL 持久化 incident ID、去重键、前后快照引用、状态、公开调查轨迹、预算、报告和时间。Runtime 重启后 MUST 保留已完成结果，将中断 run 标记为 interrupted，且 MUST NOT 自动重放模型或远端工具。

#### Scenario: 调查中 Runtime 重启

- **WHEN** Runtime 在一次工具调用后、报告生成前重新启动
- **THEN** incident 保留已有证据并显示 interrupted，等待新的显式恢复动作而不自动调用工具

### Requirement: 调查不得绕过既有操作审批

Investigation Agent MUST 只观察和报告。incident、根因结论或用户追问均 MUST NOT 自动创建或执行写操作；任何处理请求 SHALL 进入既有 Plan → Confirm → Execute → Verify → Rollback/Cleanup 流程并重新校验当前证据与本地策略。

#### Scenario: 用户要求修复已确认的监听问题

- **WHEN** 用户从 incident 详情明确要求处理
- **THEN** 系统仅生成符合既有操作规格的候选计划，不把调查成功当作授权或执行结果

### Requirement: Windows 默认产品必须提供真实本机服务快照

Windows Node Runtime SHALL 在未配置 Coordinator 时复用既有确定性只读工具，按有界周期采集本机监听、进程与可选 Docker 服务并向 incident 快照提供完整结果。全新数据目录 MUST 以前两次完整观察作为启动稳定期，以第二次结果建立基线，并且 MUST NOT 比较前两次结果或创建启动 incident；已有持久化快照的重启 MUST 直接沿用该基线。

#### Scenario: 未配置 Coordinator 的 Windows 首次启动

- **WHEN** Windows 产品以全新数据目录启动，前两次完整观察之间出现应用监听或短命系统端口变化
- **THEN** Runtime 保存两次观察、以第二次结果建立基线，不创建启动 incident，也不调用模型

#### Scenario: 本机新增监听稳定出现

- **WHEN** 稳定基线建立后新增本机监听，并在现有确认窗口内持续存在
- **THEN** Runtime 自动创建 `service_added` incident；模型未配置时保留差异证据并标记 `investigation_unavailable`

### Requirement: macOS 默认产品必须提供真实本机服务快照

macOS Node Runtime SHALL 在未配置 Coordinator 时复用既有确定性只读工具，按有界周期采集本机监听、进程与可选 Docker 服务并向 incident 快照提供完整结果。全新数据目录 MUST 以前两次完整观察作为启动稳定期，以第二次结果建立基线，并且 MUST NOT 比较前两次结果或创建启动 incident；已有持久化快照的重启 MUST 直接沿用该基线。

#### Scenario: 未配置 Coordinator 的 macOS 首次启动

- **WHEN** macOS 产品以全新数据目录启动，前两次完整观察之间出现应用监听或短命系统端口变化
- **THEN** Runtime 保存两次观察、以第二次结果建立基线，不创建启动 incident，也不调用模型

#### Scenario: macOS 本机新增监听稳定出现

- **WHEN** 稳定基线建立后新增本机监听，并在现有确认窗口内持续存在
- **THEN** Runtime 自动创建 `service_added` incident；模型未配置时保留差异证据并标记 `investigation_unavailable`
