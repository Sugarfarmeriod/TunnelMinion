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

### Requirement: Runtime 必须维护公开的信息缺口状态

每个本机调查 run MUST 根据 incident 事件类型维护已尝试工具、成功证据引用、剩余信息缺口和当前允许工具，并在每轮模型调用前把该状态作为程序约束提供。信息缺口变化和模型合同纠正 MUST 写入公开调查轨迹；系统 MUST NOT 保存隐藏思维链，也 MUST NOT 把评测场景 ID、期望根因、必要工具评分字段或工具夹具参数注入模型上下文。

#### Scenario: 新增服务取得监听证据后仍缺进程归属

- **WHEN** 本机 `service_added` 已成功执行监听工具但尚未执行进程摘要工具
- **THEN** Runtime 公开记录监听证据与剩余进程归属缺口，下一轮只允许能填补该缺口的只读工具，且不得接受确认终态

#### Scenario: 可达性工具缺少目标地址

- **WHEN** 本机可达性类 incident 尚未成功读取包含目标地址的节点摘要
- **THEN** Runtime 不向模型暴露可达性探测工具，不猜测或注入目标地址，并把节点地址标记为剩余信息缺口

#### Scenario: 评测评分字段保持隔离

- **WHEN** 固定 incident 矩阵通过真实 Runtime 调用模型
- **THEN** 模型请求只包含生产事件、受影响对象、公开信息缺口、允许工具和实际工具结果，不包含评分答案或场景标识

#### Scenario: 根因评分拒绝相反状态

- **WHEN** 一个预期确认的固定场景报告包含全部对象、地址和端口锚点，但对监听、进程或容器状态给出与期望相反的结论
- **THEN** 该场景不得计为根因成功，且 v4 数据集校验必须拒绝未声明反向状态词的预期确认场景

### Requirement: Agent 只能动态选择既有只读工具

Investigation Agent SHALL 只能从当前策略、平台、节点状态、事件证据路径和任务阶段允许的 `get_node_summary`、`get_wireguard_status`、`list_network_listeners`、`get_process_summary`、`list_docker_services`、`probe_service_reachability` 中选择工具。所有参数 MUST 由 Tool Runtime 校验；本轮附带可信参数字典时，实际参数 MUST 与它完全相等，空字典 MUST 禁止附加可选参数，未附带可信参数时仍按普通 schema 校验。系统 MUST NOT 提供 Shell、Python、未知工具或任何写操作。当前节点的本机工具 MUST 只向 `local_observation` 来源的 incident 暴露和执行。本机 `service_added` 的证据路径 MUST 覆盖监听与进程，本机 `service_removed` MUST 覆盖进程与 Docker 生命周期，本机 `node_offline` MUST 覆盖节点与 WireGuard，本机 `local_only` MUST 覆盖节点、监听与目标可达性，本机 `remote_unreachable` MUST 覆盖节点、WireGuard 与目标可达性；`state_stale` MUST 不执行本机工具并以当前信息不可用收口。每轮只能暴露仍能填补缺口且依赖已满足的相关工具；模型未按要求选择工具时，Runtime MUST 先进行一次有界纠正，再通过同一 Tool Runtime 执行一个确定性只读 fallback。纠正和 fallback MUST 受轮次、平台策略、参数校验、调用预算与审计约束，且 MUST NOT 应用于远端、Coordinator 目录或聚合来源。

#### Scenario: Agent 需要区分进程退出与容器退出

- **WHEN** 本机 `service_removed` 的进程与 Docker 生命周期证据仍不完整且两项工具均可用
- **THEN** Agent 从当前相关工具中选择一项，Runtime 执行并记录选择、证据和剩余缺口，随后只保留尚未覆盖的相关工具

#### Scenario: 模型请求执行未知命令

- **WHEN** 模型请求 Shell、Python、写操作或注册表外工具
- **THEN** Runtime 拒绝请求、不执行系统调用，并将该步骤记录为调查失败证据

#### Scenario: 本机首轮返回合法无工具报告

- **WHEN** `local_observation` 来源的 incident 仍有可获取的信息缺口，但模型返回结构有效且没有工具调用的终态
- **THEN** Runtime 不接受提前停止，公开记录一次合同纠正并使用相同的当前允许工具再次请求模型选择

#### Scenario: 模型纠正后仍未选择工具

- **WHEN** 同一调查已经使用一次合同纠正机会，模型在仍有可获取缺口时再次没有调用允许工具
- **THEN** Runtime 从当前证据路径选择第一个可用只读工具，经既有 Tool Runtime 执行，并把该调用明确记录为 fallback 而不是模型选择

#### Scenario: 模型服务暂时返回无效兼容响应

- **WHEN** Provider 将一次无效兼容响应明确标记为可重试
- **THEN** Runtime 在原模型轮次和墙钟预算内公开记录并重试一次，不执行工具；第二次无效响应或不可重试错误仍按原失败路径结束

#### Scenario: 本机新增服务只能选择场景相关工具

- **WHEN** `local_observation` 来源的 `service_added` 进入调查循环
- **THEN** 首轮只暴露 `list_network_listeners`，成功取得监听结果后只暴露 `get_process_summary`，且不暴露节点、WireGuard、Docker 或可达性工具

#### Scenario: 可达性探测等待节点地址证据

- **WHEN** `local_only` 或 `remote_unreachable` 尚未成功执行 `get_node_summary`
- **THEN** Runtime 只暴露当前相关的非探测工具；节点摘要成功后才允许模型用其中的地址和 incident 端口调用 `probe_service_reachability`，Tool Runtime 拒绝任何不匹配该地址或端口的调用且不执行适配器

#### Scenario: 模型给可信调用追加可选参数

- **WHEN** Runtime 已为本轮工具指定空参数或固定探测目标，而模型额外加入 `limit`、超时或其他 schema 允许的可选参数
- **THEN** Tool Runtime 以参数不匹配拒绝该调用，且适配器不得收到请求

#### Scenario: 后续工具调用与终态 Schema 同时启用

- **WHEN** 信息缺口已清空的轮次携带调查终态 JSON Schema，模型返回 `content=null` 和一个工具调用
- **THEN** Provider 先保留工具调用并交给 Tool Runtime 执行，只在没有工具调用时解析结构化终态正文

#### Scenario: 远端来源首轮没有工具调用

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 首轮没有工具调用
- **THEN** Runtime 不执行纠正或本机 fallback，合法的 evidence-free `insufficient_evidence` 可以保留，无效响应按现有失败路径结束

#### Scenario: 远端来源主动请求本机工具

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 中，模型主动请求当前节点的监听、进程或其他本机工具
- **THEN** Runtime 不向该请求暴露或执行本机工具，也不把当前节点的工具结果记录为远端对象证据

### Requirement: 调查必须在明确停止条件下生成证据化报告

Runtime MUST 对模型轮次、工具调用数、墙钟时间和上下文使用设置上限，并在事件证据路径完整且根因证据充分、必要信息不可获得、证据冲突、预算耗尽、用户取消或运行失败时停止。报告 SHALL 区分已确认事实、候选解释、未知项、停止原因和证据引用。确认结论 MUST 引用该事件证据路径中全部成功且生产输出声明可用的工具结果；`degraded` 或 `unavailable` 输出不得填补信息缺口。Runtime MUST 对每类非陈旧本机事件至少执行一个与触发快照对应的确定性冲突检查。模型遗漏引用时 Runtime MUST 允许至多一次终态纠正，第二次仍不满足时 MUST 保留该无依据尝试并降级为 `insufficient_evidence`。没有有效证据、证据路径未完成或只存在未证实候选解释的断言 MUST NOT 成为确认结论。

#### Scenario: 根因证据充分

- **WHEN** 一个候选根因覆盖当前事件的完整证据路径、引用全部对应 tool run 且不存在冲突关键证据
- **THEN** Agent 停止额外调用并生成引用这些 tool run 的确认结论

#### Scenario: 远端不可达只有现象证据

- **WHEN** `remote_unreachable` 已取得节点、WireGuard 与目标探测结果，但没有监听或进程证据可证明具体故障层
- **THEN** Runtime 保留全部只读证据并以 `insufficient_evidence` 停止，不调用模型把探测失败扩写成未监听、进程退出或崩溃根因

#### Scenario: 模型过早返回确认终态

- **WHEN** 模型返回 `evidence_sufficient`，但当前事件仍有未尝试工具或终态没有引用全部所需成功证据
- **THEN** Runtime 不确认 incident；有可获取缺口时继续取证，只有引用遗漏时进行至多一次终态纠正

#### Scenario: 调用预算耗尽

- **WHEN** 调查已达到最大工具调用数且当前事件仍有未覆盖的信息缺口
- **THEN** Runtime 不再调用模型或工具，报告已有事实、未知项和 `budget_exhausted` 停止原因

#### Scenario: 墙钟预算在取得部分工具证据后耗尽

- **WHEN** 调查已取得一项或多项成功工具证据，但后续模型调用达到墙钟上限
- **THEN** Runtime 从已持久化调查轨迹恢复这些工具证据，以 `budget_exhausted` 结束且不丢失用户已看到的进展

#### Scenario: 必要工具不可用

- **WHEN** 证据路径中的必要工具失败、被策略拒绝或参数无法通过校验
- **THEN** Runtime 停止后续取证并以 `insufficient_evidence` 结束，不用模型常识补写实时事实，已有工具轨迹保持可见

#### Scenario: 工具调用成功但生产采集结果不可用

- **WHEN** 必要只读工具执行状态为成功，但结构化输出的 `availability` 为 `degraded` 或 `unavailable`
- **THEN** Runtime 不把它记为成功信息缺口证据，保留该 tool run 并直接以 `insufficient_evidence` 结束

#### Scenario: 实时证据与触发快照冲突

- **WHEN** 成功的只读工具结果与 incident 触发快照对同一状态给出冲突结论
- **THEN** Agent 保持候选或未知状态并以 `insufficient_evidence` 结束，不把任一侧单独升级为确认根因

#### Scenario: 环回快照与非环回监听冲突

- **WHEN** `local_only` 触发快照声明目标端口只在本机可用，但实时监听结果显示同一端口绑定 `0.0.0.0` 或其他非环回地址
- **THEN** Runtime 标记证据冲突、停止追加取证并禁止确认根因

#### Scenario: 取得工具证据后调查结构失败

- **WHEN** 至少一个只读工具结果已写入公开轨迹，后续模型响应或结构处理失败
- **THEN** Runtime 从持久化 incident 恢复最新轨迹和工具证据，以 `failed` 结束且不得把已有进展清空

#### Scenario: 陈旧状态没有可用当前证据

- **WHEN** `state_stale` incident 表明当前节点或服务事实已超过新鲜度边界
- **THEN** Runtime 不调用本机工具或模型补写当前事实，保留差异证据并以 `insufficient_evidence` 结束

### Requirement: Incident 与调查状态必须持久化并安全恢复

系统 SHALL 持久化 incident ID、去重键、前后快照引用、状态、公开调查轨迹、预算、报告和时间。Runtime 重启后 MUST 保留已完成结果，将中断 run 标记为 interrupted，且 MUST NOT 自动重放模型或远端工具。

#### Scenario: 调查中 Runtime 重启

- **WHEN** Runtime 在一次工具调用后、报告生成前重新启动
- **THEN** incident 保留已有证据并显示 interrupted，等待新的显式恢复动作而不自动调用工具

### Requirement: 调查不得绕过既有操作审批

Investigation Agent MUST 只观察和报告。incident、根因结论或用户追问均 MUST NOT 自动创建、批准或执行写操作；产品只能为已确认、当前快照仍可定位且由现有安全操作支持的 incident 提供不可信候选计划预填。任何处理请求 SHALL 进入既有 Plan → Confirm → Execute → Verify → Rollback/Cleanup 流程，并重新校验当前证据、合格 peer、本地策略和目标节点授权。

#### Scenario: 用户要求处理已确认的远端监听问题

- **WHEN** 用户从已确认的远端 `local_only` service incident 详情明确要求处理
- **THEN** 系统只打开符合既有操作规格的预填候选计划表单，不把调查成功当作用户确认、授权或执行结果

#### Scenario: Incident 上下文已经陈旧或预填值被修改

- **WHEN** service 快照不再新鲜、目标 peer 不再合格，或浏览器修改了预填目标与端口
- **THEN** 既有操作流程不继承 incident 结论或 URL 参数的可信度；任何提交只按实际参数重新校验合格 peer、最新证据、候选计划和授权，并不得标记为原 incident 的权威处理结果

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
