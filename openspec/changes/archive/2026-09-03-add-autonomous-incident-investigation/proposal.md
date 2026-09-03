## Why

TunnelMinion 已经能够确定性地展示节点、服务和只读诊断证据，但仍要求用户主动打开聊天并提出正确问题。产品需要把这些既有能力收敛为“平时自动观察、变化时自主调查、总览直接给出证据化结论”的个人多设备故障调查闭环。

## What Changes

- 定期生成有界、可比较的节点与服务状态快照，确定性识别新增、消失、离线、陈旧、仅本机可用和远端不可达事件；正常刷新不调用模型。
- 仅为满足触发规则的 incident 启动一个 Investigation Agent。Agent 维护候选根因，按证据缺口选择既有六个只读工具，更新或淘汰假设，并在证据充分、信息不足或预算耗尽时停止。
- 保存脱敏、可恢复的 incident、调查轨迹、证据引用、结论、未知项和停止原因；模型失败不影响快照、事件检测与总览。
- 把 incident 卡片和调查轨迹加入 Overview，并提供绑定当前 incident 的小型追问对话与动态建议问题；聊天不再承担产品主入口。
- 增加固定故障矩阵与评估指标：根因成功率、工具选择率、非必要调用率、无证据断言率、失败恢复率和延迟。
- 继续复用服务目录、Overview、上下文预算、证据模型、六个只读工具及既有操作审批链。需要处理时仍进入 Plan → Confirm → Execute → Verify → Rollback/Cleanup，调查本身不获得写权限。
- 非目标：多 Agent、Reviewer、Agent 自写 Shell/Python、自动修改防火墙或 WireGuard、正常刷新调用模型、新 relay、新网络 Provider、公共 SaaS、企业 RBAC、通用 AIOps 平台。只有真实评测证明单 Agent 存在明确瓶颈时，才另建 change 评估扩展。

## Capabilities

### New Capabilities

- `autonomous-incident-investigation`: 规定确定性快照差异、incident 触发、单 Investigation Agent 的假设—工具—证据—停止循环及持久化调查结果。

### Modified Capabilities

- `local-product-interface`: 将 Overview 提升为 incident 主入口，展示调查状态、轨迹、结论、未知项、建议问题和绑定 incident 的上下文追问。
- `agent-evaluation`: 增加固定 incident 故障矩阵及根因、工具选择、非必要调用、无证据断言、失败恢复和延迟指标。

## Impact

- 预计影响后台状态观测与调度、Agent 运行状态、持久化存储、Overview 只读 API/React 视图及离线评估数据集。
- 复用 `get_node_summary`、`get_wireguard_status`、`list_network_listeners`、`get_process_summary`、`list_docker_services`、`probe_service_reachability`，不新增任意命令工具。
- 不修改真实网络、模型 Provider、秘密保存方式、Coordinator 信任边界或现有操作授权语义。
