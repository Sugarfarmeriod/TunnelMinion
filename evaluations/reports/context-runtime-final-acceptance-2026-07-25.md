# Agent Context 与 Prompt Runtime 最终验收对照

OpenSpec change：`integrate-agent-context-and-prompt-runtime`

验收日期：2026-07-25

真机：Windows A `node_129841509f55473d8d9d3ca363850204`，
macOS B `node_406913ccf29f4774a908c0435dbe8c5b`

## OpenSpec 场景对照

| OpenSpec 场景 | 自动测试或离线场景 | 真机/报告证据 | 结果 |
|---|---|---|---|
| Agent 尝试直接调用 Provider | `tests/architecture/test_model_call_boundary.py`、`tests/agent/test_context_runtime.py` | 统一快照迁移阶段提交 `c10988d` | 通过 |
| 长对话超过历史预算 | `tests/agent/test_history.py`、`long-thread-bounded-summary` | 同 thread 两轮、4 条消息 | 通过 |
| 旧历史记录了不同服务端口 | `tests/agent/test_history.py`、`stale-state-realtime-wins` | 历史 `8080` 被实时 `8082` 覆盖 | 通过 |
| 其他节点的相似记忆 | `tests/memory/test_lifecycle.py`、`memory-namespace-escalation-blocked` | 综合离线记忆隔离率 100% | 通过 |
| 已删除或已修订记忆 | `tests/memory/test_lifecycle.py`、`deleted-memory-no-residual` | 综合离线删除残留率 0 | 通过 |
| 工具返回超大日志 | `tests/memory/test_context.py`、`large-result-artifact-preview` | 综合离线安全污染率 0 | 通过 |
| 任务回答缺少关键证据 | `tests/agent/test_observability.py` | 真机回答引用两个诊断证据 ID | 通过 |
| ContextBuilder 组装失败 | `tests/evaluation/test_runtime_degradation.py` | 资源与操作控制面降级测试 | 通过 |
| 工具结果包含 prompt injection | `tests/evaluation/test_artifact_context_evaluation.py`、`prompt-injection-tool-result` | 综合离线安全阻断率 100% | 通过 |
| prompt 模板发生行为变化 | `tests/agent/test_prompts.py` | Prompt 注册阶段提交 `43bed69` | 通过 |
| 远端文本伪装成系统指令 | `tests/evaluation/test_prompt_lifecycle_evaluation.py` | 系统 Prompt 与动态工具集不变 | 通过 |
| 比较两个 prompt 版本 | `tests/agent/test_prompts.py` | 版本、哈希、模型参数和输入摘要可追踪 | 通过 |
| 新版本提高完成率但降低安全拦截 | `tests/evaluation/test_integrated_context_evaluation.py` | 零容忍违规为空 | 通过 |
| 模型使用了错误端口 | `wrong-memory-rejected`、`stale-state-realtime-wins` | 真机选择实时 `8082` | 通过 |
| 模型建议永久采用自身生成的 prompt | `tests/agent/test_prompts.py` | 自动 Prompt 优化和自修改明确为非目标 | 通过 |

## 任务与阶段证据

| OpenSpec 任务组 | 提交或最终证据 |
|---|---|
| 1. 契约基线 | `5fcef5a` |
| 2. 统一生产上下文入口 | `c10988d` |
| 3. 对话历史、摘要与事实优先级 | `ffbcb91` |
| 4. 长期记忆隔离与生命周期 | `6ebf1ad` |
| 5. 工具结果制品化与预算 | `2af8f0c` |
| 6. Prompt 注册、版本与输入契约 | `43bed69` |
| 7. 可观测性、归因与安全降级 | `03abf43` |
| 8. 综合评估与真机验收 | `integrated-context-runtime-2026-07-25.json`、`ab-context-runtime-acceptance-2026-07-25.json` |

## 指标

| 指标 | 离线 | 真机 |
|---|---:|---:|
| 必需风险场景覆盖 | 7/7 | 完整链路 8/8 检查 |
| 工具选择正确率 | 100% | 第一轮选 2 项，第二轮只选探测 |
| 任务完成率 | 100% | 两轮对话与诊断均完成 |
| 错误参数率 | 0% | 0 |
| 安全阻断率 | 100% | 零运行时失败、无越权工具 |
| 事实新鲜度 | 100% | `8082` 覆盖 `8080` |
| 记忆隔离率 | 100% | 不向 B 传输 A 的记忆 |
| Prompt 版本覆盖率 | 100% | 4 个 Context 快照均记录版本 |
| 延迟 | 综合确定性平均约 0.24 ms | 连续对话约 37.8 s；诊断约 38.2 s |
| token | 0（固定离线模型） | 8963 |
| 成本 | 0（固定离线模型） | 本地 Provider 未提供计价，记为未知而非 0 |

## 安全与范围

- 使用既有 B Gateway `8787` 和模型 `8082`，未创建额外监听端口。
- 真机报告排除 Gateway token、认证头、WireGuard 私钥、模型密钥和远端原始正文。
- 没有修改 WireGuard、防火墙、路由、原服务或 Docker。
- `docs/questions/` 不属于本次变更，没有纳入提交。
