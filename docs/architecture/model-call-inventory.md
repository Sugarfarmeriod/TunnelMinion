# 模型调用盘点与迁移基线

本清单固定 `integrate-agent-context-and-prompt-runtime` 实施前的模型调用面。架构测试会拒绝新增未登记的
`ModelRequest` 构造或 Provider `complete()` 直调；第二阶段将逐项把这些入口迁移到
`ContextBuilder -> ContextSnapshot -> Provider`。

| 调用路径 | 类型 | 当前 prompt 与消息来源 | 工具 schema | 历史 / 记忆 | 工具结果 / 证据 | 迁移要求 |
| --- | --- | --- | --- | --- | --- | --- |
| `agent/langchain_model.py::_complete` | 本地对话与 LangChain Agent | `agent/runtime.py` 的系统 prompt、当前问题及 LangChain 工具循环消息 | 当前 run 动态绑定的只读工具 | 当前未注入 thread 历史或长期记忆 | LangChain 工具消息 | 统一由 Builder 生成对话快照 |
| `agent/diagnostics.py::answer` | 跨节点诊断解释 | 文件内固定系统说明、用户问题和确定性诊断报告 | 无 | 无 | 最新 `CrossNodeDiagnosticReport` | 诊断证据作为高优先级引用进入快照 |
| `agent/planning.py::generate` | L2 候选计划说明 | `temporary-service-sharing-plan@v1` 与结构化用户/诊断数据 | JSON response schema | 无 | 最新诊断及 tool run 引用 | 保留确定性字段，仅迁移说明文本上下文 |
| `model/configuration.py::_validate_provider`（两次） | Provider 能力验证 | 固定能力探测消息 | 固定工具 schema 与 JSON response schema | 无 | Provider 响应 | 使用独立的 `provider-validation` 快照 |
| `scripts/run_real_model_evaluation.py` | 手工真实模型评估 | 版本化数据集中的脚本消息 | 数据集声明工具 | 仅脚本内历史 | fixture 或真实 Provider 结果 | 保持非生产入口，改用固定评估快照 |

当前没有独立摘要模型和后台模型任务。`src/tunnelminion/evaluation/fakes.py::FakeModel` 只允许在离线评估
路径使用，生产配置不能选择它。

## 基线场景

`evaluations/baselines/context-runtime-v1.json` 从 `tunnelminion-mvp@v1` 固定两个代表场景：

- `normal-node-summary`：典型对话，固定回答、`get_node_summary` 选择、35 ms、42 tokens、成本 0。
- `loopback-pdf-diagnosis`：跨节点诊断，固定三项工具选择、210 ms、114 tokens、成本 0。

这些延迟和成本是离线记录值，只用于比较迁移前后行为是否漂移，不代表 10.77.0.1 真实模型的实时性能。
