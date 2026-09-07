## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Agent 只能动态选择既有只读工具

Investigation Agent SHALL 只能从当前策略、平台、节点状态、事件证据路径和任务阶段允许的 `get_node_summary`、`get_wireguard_status`、`list_network_listeners`、`get_process_summary`、`list_docker_services`、`probe_service_reachability` 中选择工具。所有参数 MUST 由 Tool Runtime 校验；系统 MUST NOT 提供 Shell、Python、未知工具或任何写操作。当前节点的本机工具 MUST 只向 `local_observation` 来源的 incident 暴露和执行。本机 `service_added` 的证据路径 MUST 覆盖监听与进程，本机 `service_removed` MUST 覆盖进程与 Docker 生命周期，本机 `node_offline` MUST 覆盖节点与 WireGuard，本机 `local_only` MUST 覆盖节点、监听与目标可达性，本机 `remote_unreachable` MUST 覆盖节点、WireGuard 与目标可达性；`state_stale` MUST 不执行本机工具并以当前信息不可用收口。每轮只能暴露仍能填补缺口且依赖已满足的相关工具；模型未按要求选择工具时，Runtime MUST 先进行一次有界纠正，再通过同一 Tool Runtime 执行一个确定性只读 fallback。纠正和 fallback MUST 受轮次、平台策略、参数校验、调用预算与审计约束，且 MUST NOT 应用于远端、Coordinator 目录或聚合来源。

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

#### Scenario: 本机新增服务按依赖开放工具

- **WHEN** `local_observation` 来源的 `service_added` 进入调查循环
- **THEN** 首轮只暴露 `list_network_listeners`，成功取得监听结果后只暴露 `get_process_summary`，且不暴露节点、WireGuard、Docker 或可达性工具

#### Scenario: 可达性探测等待节点地址证据

- **WHEN** `local_only` 或 `remote_unreachable` 尚未成功执行 `get_node_summary`
- **THEN** Runtime 只暴露当前相关的非探测工具；节点摘要成功后才允许模型用其中的地址和 incident 端口调用 `probe_service_reachability`，Tool Runtime 拒绝任何不匹配该地址或端口的调用且不执行适配器

#### Scenario: 后续工具调用与终态 Schema 同时启用

- **WHEN** 信息缺口已清空的轮次携带调查终态 JSON Schema，模型返回 `content=null` 和一个工具调用
- **THEN** Provider 先保留工具调用并交给 Tool Runtime 校验，只在没有工具调用时解析结构化终态正文

#### Scenario: 远端来源首轮没有工具调用

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 首轮没有工具调用
- **THEN** Runtime 不执行纠正或本机 fallback，合法的 evidence-free `insufficient_evidence` 可以保留，无效响应按现有失败路径结束

#### Scenario: 远端来源主动请求本机工具

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 中，模型主动请求当前节点的监听、进程或其他本机工具
- **THEN** Runtime 不向该请求暴露或执行本机工具，也不把当前节点的工具结果记录为远端对象证据

### Requirement: 调查必须在明确停止条件下生成证据化报告

Runtime MUST 对模型轮次、工具调用数、墙钟时间和上下文使用设置上限，并在事件证据路径完整且根因证据充分、必要信息不可获得、证据冲突、预算耗尽、用户取消或运行失败时停止。报告 SHALL 区分已确认事实、候选解释、未知项、停止原因和证据引用。确认结论 MUST 引用该事件证据路径中全部成功工具结果；模型遗漏引用时 Runtime MUST 允许至多一次终态纠正，第二次仍不满足时 MUST 保留该无依据尝试并降级为 `insufficient_evidence`。没有有效证据或证据路径未完成的断言 MUST NOT 成为确认结论。

#### Scenario: 根因证据充分

- **WHEN** 一个候选根因覆盖当前事件的完整证据路径、引用全部对应 tool run 且不存在冲突关键证据
- **THEN** Agent 停止额外调用并生成引用这些 tool run 的确认结论

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

#### Scenario: 实时证据与触发快照冲突

- **WHEN** 成功的只读工具结果与 incident 触发快照对同一状态给出冲突结论
- **THEN** Agent 保持候选或未知状态并以 `insufficient_evidence` 结束，不把任一侧单独升级为确认根因

#### Scenario: 陈旧状态没有可用当前证据

- **WHEN** `state_stale` incident 表明当前节点或服务事实已超过新鲜度边界
- **THEN** Runtime 不调用本机工具或模型补写当前事实，保留差异证据并以 `insufficient_evidence` 结束
