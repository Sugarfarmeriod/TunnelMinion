## ADDED Requirements

### Requirement: 远端 incident 必须只使用目标 Gateway 的实时只读证据

当 incident 的目标不是当前节点、来源不是 `local_observation` 且事件仍可实时调查时，Runtime SHALL 只按稳定 target node ID 从本机显式授权 peer 解析目标 Gateway，在模型外完成认证、节点摘要身份核验和实时能力过滤，再把目标节点的相关只读工具注入同一个 Investigation Agent。调用上下文 MUST 把当前产品节点记录为 caller、incident 目标记录为 execution；Coordinator/聚合快照、模型输出或 endpoint 文本 MUST NOT 自行授予调用权限。

#### Scenario: Windows 调查 macOS 的环回监听 incident

- **WHEN** Windows 产品从 Coordinator/聚合快照得到指向 macOS peer 的 `local_only` incident，且该 peer 已显式授权并通过 Gateway 身份与能力预检
- **THEN** Agent 只看到 macOS 目标摘要与监听证据路径，所执行工具的 caller 为 Windows、execution 为 macOS，确认结论引用目标 Gateway 返回的 `tool_run_id`

#### Scenario: 远端目标没有显式授权 peer

- **WHEN** 快照包含远端 node ID，但本机没有该目标的有效 static peer、凭据或允许工具
- **THEN** Runtime 不连接快照或模型提供的任意 endpoint，不暴露本机工具，并以 `insufficient_evidence` 保存授权证据不可用状态

#### Scenario: Gateway 摘要身份与目标不一致

- **WHEN** 目标 Gateway 返回的 node ID 或平台与 incident 目标不一致
- **THEN** Runtime 拒绝全部远端工具，不把摘要或后续结果记为目标证据，并以 `insufficient_evidence` 停止

### Requirement: 远端调查必须维护独立证据路径并失败关闭

Runtime MUST 为可调查的远端 service 事件维护目标节点证据路径：service added 覆盖节点摘要、监听与进程，service removed 覆盖节点摘要、进程与 Docker，local-only 覆盖节点摘要与监听，remote-unreachable 覆盖节点摘要、监听与进程。远端摘要预检 MUST 作为公开证据和调用预算的一部分；node-offline 与 state-stale MUST NOT 尝试连接目标。远端路径 MUST NOT 执行请求节点本机工具或确定性 fallback；必要能力、调用或输出不可用时 SHALL 保留已有证据并以 `insufficient_evidence` 停止。

#### Scenario: 远端模型纠正后仍未选择工具

- **WHEN** 远端 service incident 仍有可获取信息缺口，模型在一次合同纠正后仍未选择当前允许工具
- **THEN** Runtime 不替模型执行远端 fallback，不调用请求节点本机工具，并以证据不足结束

#### Scenario: 远端必要工具执行失败

- **WHEN** 目标摘要已经成功，但后续监听或进程工具超时、被拒绝或返回不可用结果
- **THEN** 调查公开保留摘要和失败 tool run，以 `insufficient_evidence` 停止且不生成确认根因

#### Scenario: 远端节点已离线或状态陈旧

- **WHEN** incident 类型为 `node_offline` 或 `state_stale`
- **THEN** Runtime 只保留触发快照，不发起 Gateway、模型工具或本机 fallback 调用
