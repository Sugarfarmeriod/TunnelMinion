# TunnelMinion 的 Prompt、Context、Runtime 与 Harness 概念映射

这份文档用于把零散概念对回当前代码，不规定业界必须有几层，也不把“大模型调用次数多”当成
项目成熟度。

| 标准概念 | TunnelMinion 当前对应物 | 负责什么 | 不负责什么 |
|---|---|---|---|
| Prompt 工程 | 只读解释提示、`temporary-service-sharing-plan:v1` | 规定模型角色、输出格式和不可信数据边界 | 不授予工具或操作权限 |
| Context 工程 | 诊断报告、证据引用、候选计划上下文、版本和大小追踪 | 选择当前任务需要的实时事实，并标记来源和裁剪 | 不用历史记忆覆盖实时状态 |
| Agent Runtime | `CrossNodeDiagnosticAgent`、只读 LangChain 循环 | 编排模型、诊断和候选计划 | 不直接持有写适配器 |
| Tool Runtime | `ToolRegistry`、`ToolRuntime`、固定平台适配器 | 校验 L0 工具、参数、平台、预算和结果 | 不执行 L2 |
| Operation Runtime | `OperationWorkflow`、Gateway operation service | Plan → Authorize → Execute → Verify → Expire/Rollback | 不接受聊天文本当授权 |
| Harness | Provider 适配、能力发现、取消/超时、schema、持久化、恢复、回调验证、评测脚本 | 让不稳定模型在可重复、可观测、可恢复的外壳中工作 | 不等于一个万能框架或固定“七层” |
| 治理 | L0～L4、目标节点批准、细粒度预授权、资源所有权 | 决定谁能对什么做多大范围的动作 | 不由 prompt 或模型决定 |
| 评估 | 离线数据集、真实模型报告、A/B 验收、零容忍门禁 | 衡量字段、证据、授权、安全、完成率、延迟、token、成本 | 不以主观“看起来聪明”替代证据 |
| 可观测性 | thread/run/tool/operation ID、状态历史、脱敏 trace 和 metrics | 定位 Context、模型、工具 Harness 或治理故障 | 不记录秘密或不必要原文 |

三者关系可以理解为：

```text
Prompt：这次怎样向模型说明任务
Context：这次允许模型看见哪些事实
Harness：模型前后所有确定性约束、工具、状态、恢复、评估与治理
```

TunnelMinion 当前候选计划会记录 `prompt_id/version`、provider/model、工具 schema、证据快照、
上下文 schema、消息/结果/证据数量、输入大小、裁剪数和 token。故障分别归因到 Context、
Prompt/Model、Harness/Tool 或 Governance。模型失败只阻止新候选计划；已经批准的拒绝、撤销、
到期、恢复和清理不依赖模型。

完成度不由以下指标决定：

- prompt 有多长；
- Agent 有几个；
- 是否使用 RAG 或向量库；
- Harness 被画成几层；
- 是否能让模型自行改 prompt 或代码。

当前更重要的是：事实是否来自实时证据、权限是否由目标节点掌握、失败是否安全、资源是否可
回收、结果是否能复现。RAG、跨节点经验共享、多 Agent、自动 prompt 优化、自修改 Harness、
通用 Harness 平台和企业 SaaS/RBAC 都需要独立 change。
