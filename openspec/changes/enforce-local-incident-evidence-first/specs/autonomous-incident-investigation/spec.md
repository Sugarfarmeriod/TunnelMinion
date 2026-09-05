## MODIFIED Requirements

### Requirement: Agent 只能动态选择既有只读工具

Investigation Agent SHALL 只能从当前策略、平台、节点状态和任务阶段允许的 `get_node_summary`、`get_wireguard_status`、`list_network_listeners`、`get_process_summary`、`list_docker_services`、`probe_service_reachability` 中选择工具。所有参数 MUST 由 Tool Runtime 校验；系统 MUST NOT 提供 Shell、Python、未知工具或任何写操作。当前节点的本机工具 MUST 只向 `local_observation` 来源的 incident 暴露和执行。对于该来源的服务 incident，如果模型首轮没有选择工具，Runtime MUST 通过同一 Tool Runtime 执行一次 `list_network_listeners` 后再继续模型循环；该规则 MUST 同时覆盖结构有效和结构无效的首轮无工具响应，且 MUST NOT 应用于远端、Coordinator 目录或聚合来源。

#### Scenario: Agent 需要区分进程退出与端口映射变化

- **WHEN** 当前证据不足且进程摘要与 Docker 服务工具均可用
- **THEN** Agent 选择填补证据缺口所需的工具，Runtime 记录候选、选择和排除原因

#### Scenario: 模型请求执行未知命令

- **WHEN** 模型请求 Shell、Python 或注册表外工具
- **THEN** Runtime 拒绝请求、不执行系统调用，并将该步骤记录为调查失败证据

#### Scenario: 本机服务首轮返回合法无工具报告

- **WHEN** `local_observation` 来源的服务 incident 首轮要求工具，但模型返回结构有效且没有工具调用的证据不足报告
- **THEN** Runtime 忽略该轮提前停止意图，通过既有 Tool Runtime 执行一次 `list_network_listeners`，并把真实结果交回下一轮模型判断

#### Scenario: 本机服务首轮返回无效无工具响应

- **WHEN** `local_observation` 来源的服务 incident 首轮既没有工具调用也没有合法调查结构
- **THEN** Runtime 通过既有 Tool Runtime 执行一次 `list_network_listeners`，且仍受平台策略、参数校验、调用预算和审计约束

#### Scenario: 远端来源首轮没有工具调用

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 首轮没有工具调用
- **THEN** Runtime 不执行任何本机兜底工具，合法证据不足报告可以保留，无效响应按现有失败路径结束

#### Scenario: 远端来源主动请求本机工具

- **WHEN** 远端、Coordinator 目录或聚合来源的 incident 中，模型主动请求当前节点的监听、进程或其他本机工具
- **THEN** Runtime 不向该请求暴露或执行本机工具，也不把当前节点的工具结果记录为远端对象证据
