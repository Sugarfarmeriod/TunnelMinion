# 看懂一次 Agent 调查

总览里的“调查详情”展示的是已经保存下来的公开过程，不会因为打开页面再次调用模型或工具。

下面以当前已经支持结构化状态的远端 `local_only` 场景为例：

1. 确定性程序先发现服务或节点发生变化，创建 Incident。
2. Harness 读取对应 Skill、已有事实、未知项和已经完成的步骤。
3. 模型只在允许的只读工具中选择下一步；它不能直接操作系统。
4. 程序在指定节点执行工具，校验结果并保存证据引用、摘要和尝试次数。
5. 证据满足这个 Skill 的停止条件时形成结论；证据不足、预算用完、失败或中断也会明确停止。

页面显示 Skill 版本、当前阶段、已用模型轮次、已用工具调用、每一步的执行节点和公开证据。这里的“工具执行成功”只说明调用完成，不等于诊断结论正确，也不代表证据已经充分。接口没有返回预算上限时，页面不会猜测剩余次数。

## 和固定诊断流程有什么区别

`CrossNodeDiagnosticWorkflow` 是手动入口使用的固定程序：它按写死的顺序读取目标节点监听、进程、Docker，再读取请求节点 WireGuard 状态并探测端口。相同输入会走相同顺序，适合明确、可重复的人工诊断。

当前远端 `local_only` Agent 根据版本化 Skill 和已有证据选择下一项允许工具。这个场景重启后可以从已保存状态继续，已成功取得的证据无需重复调用；缺证据或证据冲突时必须保留未知项。它的价值不是“自由操作网络”，而是在受控工具范围内选择取证路径，并让每一步可以复核。

其他 Incident 仍沿用各自已有的调查路径。接口没有结构化状态时，页面只保留已有 report 和 trace，不补造 Skill、次数或恢复能力。

两条路径都会经过 Tool Runtime 的参数校验、节点权限和结果记录；区别在于工具顺序由固定程序决定，还是由模型在 Skill 约束下根据现有证据选择。

## 真实调用与模拟

- 真实模型报告代表模型服务确实参与了选择，但工具环境仍可能是固定 fixture，不能据此声称完成真实双机调用。
- scripted 评测用预设模型响应验证 Harness、状态恢复和停止规则，不代表真实模型能力。
- Playwright 截图使用本地 fixture，只证明页面能正确呈现契约数据，不是真机证据。
- 真实双机结果必须同时说明真实模型、两端真实工具、网络环境和授权范围。当前已完成一次手动诊断与恢复；自动 Incident 触发的真实双机闭环仍未验收。

相关证据见[固定口径 A/B 评测](../project/stages/2026-09-29-fixed-evaluation-ab.md)和[真实双机手动诊断与恢复](../project/stages/2026-10-03-real-recovery.md)。

## 单案例：为什么另一台设备访问不到服务

选用 [candidate-1.json](../../evaluations/reports/incident-ab-deepseek-2026-09-30/candidate-1.json)
中的 `scenarios[scenario_id=remote-macos-loopback-listener]`。这是 2026-09-30 保存的
`deepseek-flash` 真实模型调用，工具输出是固定 fixture；本页只复核已有记录，没有重新调用模型或部署服务。
运行提交、数据与 Prompt 哈希见同目录 [manifest.json](../../evaluations/reports/incident-ab-deepseek-2026-09-30/manifest.json)。

### 输入：变化不是模型猜出来的

[数据集](../../evaluations/datasets/autonomous-incidents-v6.json)中同名场景把端口 `43123`
从 `network` 变成 `loopback`，期望事件为 `local_only`。记录中的请求端是 Windows，目标端是 macOS，
快照来源为 `coordinator_directory`。确定性观察路径产生事件后，调查器收到 Incident；模型负责调查，
不负责凭空发现这次变化。这里的操作系统、IP 和进程都是场景设定，不代表当前在线设备。

### 过程：三轮模型调用，不是三个模型选工具

| 时点 | 谁决定、在哪里执行 | 记录中的结果与作用 |
|---|---|---|
| 模型调用之前 | 程序做远端 `get_node_summary` 预检 | `preflight_status=success`；取得目标身份与私网状态，补入上下文和证据 |
| 第 1 轮 | 模型选择 `list_network_listeners`，程序在目标端执行 | 返回 `127.0.0.1:43123`、PID `4242`、进程 `tunnelminion-demo`；证明监听地址与进程，尚缺请求端证据 |
| 第 2 轮 | 模型选择 `probe_service_reachability`，程序在请求端执行 | 参数为 `10.77.0.1:43123`，返回 `reachable=false`、`error_code=unreachable` |
| 第 3 轮 | 模型输出结构化报告，程序校验后保存 | `status=confirmed`、`stop_reason=evidence_sufficient`；结论是服务只绑定回环，无法通过目标私网地址访问 |

探测地址和端口不是任模型随意指定：程序从目标节点摘要与 Incident 的受影响对象生成必需参数，
再交给工具执行层校验。探测工具的 `status=success` 表示探测调用完成，**不是访问成功**。
本例探测结果恰好是不可达；单独这个结果不能排除其他原因，必须和目标监听及私网证据一起判断。

记录中的 `model_calls=3`，`selected_tools` 只有监听与探测两项；另有一次程序预检。
`successful_step_count=3`、`evidence_count=3`，但 `covered_evidence_count=4`：
四类语义证据并不需要四次调用，监听查询同时提供进程和监听地址。

### 证据门：模型说“够了”不等于程序接受

[`service.local-only@1`](../../src/tunnelminion/incident/skills.py)要求四类证据：
目标进程、仅回环监听、目标私网可用、请求端不可达。程序保存工具输出中的结构化事实，并检查这些条件。
报告还必须引用已有证据、包含有支持证据的假设，覆盖必需工具证据且无冲突，才能确认根因。
引用有效不是通用的语义真实性证明；这里还有针对该 Skill 的条件校验，不能把它扩写为自动证明任何模型结论。

本例可逐一核对 `trace` 和 `evidence` 中的工具运行 ID：

- 目标摘要预检：`toolrun_187a1af70c13448bbd37f5e5ab9b81e3`。
- 目标监听：`toolrun_71248ed6fc1f4b869da50eae14621dc7`。
- 请求端探测：`toolrun_1a303155f3e14560accfc4a275e3367e`。

本例没有 fallback、重复成功调用或过早停止，`unknowns=[]`。这只描述该条记录。
其他路径中，缺少必要证据或证据冲突会保留未知并停止；无授权、工具不可用、预算耗尽、取消和模型不可用
也有明确终态。不能把这些失败写成“调查已完成且根因已确认”。

### 页面与代码：从展示回到责任边界

| 页面信息 | 数据与实现入口 | 本例怎样核对 |
|---|---|---|
| Skill、阶段、已用次数 | `incident.investigation`；调查器的 `_ensure_skill_state`、`_increment_model_round` | 报告有 Skill 版本与三轮模型调用，但没有完整页面状态对象，不据此补造页面截图 |
| 工具步骤、执行角色、证据引用 | `investigation.steps`；`_record_skill_step`；Skill 的 `execution` | 摘要与监听在目标端，探测在请求端；运行 ID 与公开轨迹对应 |
| 已知事实、仍未知、停止原因 | `_skill_observations`、`_skill_can_confirm`、`_apply_decision` | 四类证据覆盖 `4/4`，停止为 `evidence_sufficient` |
| 结论与公开调查轨迹 | `incident.report`、`incident.trace`；`InvestigationDetails` | 结论和工具先后顺序可直接查报告；打开详情不再次执行工具 |

代码入口：[`IncidentInvestigator._run_loop`](../../src/tunnelminion/incident/investigation.py)、
[`InvestigationDetails`](../../frontend/src/features/overview/InvestigationDetails.tsx)。
旧记录缺少 `investigation` 时，页面保留已有报告与轨迹；不补造 Skill 状态或零次调用。

### 调查到处理：这里仍有一道边界

`confirmed` 是调查终态，不是写操作授权。本报告没有 Operation 的批准、执行或清理记录。
用户要临时恢复访问时，另走[受控恢复链](../project/stages/2026-09-30-incident-repair-chain.md)：
候选计划先校验来源，由目标节点确认，再执行、独立验证和清理。不能把本案例称为自动修复成功。

简短讲法：程序发现服务从网络监听变为仅本机监听，先确认目标身份；模型在允许范围内选择监听查询和
请求端探测。程序负责节点路由、参数、证据和停止门，模型负责取证选择与解释。三条工具证据覆盖四类
事实后才接受结论；是否处理仍交给受控操作链。该记录证明真实模型参与了固定环境调查，不证明自动
Incident 的真实双机闭环。
