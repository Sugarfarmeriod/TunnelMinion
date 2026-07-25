## Why

TunnelMinion 已分别具备对话历史、长期记忆、工具结果和 `ContextBuilder` 等基础部件，但生产 Agent 调用尚未通过同一条可追踪的上下文组装路径，prompt 也缺少稳定版本标识。这会让长对话、过期状态、错误记忆和大工具结果难以可靠控制，也无法准确判断失败来自上下文、prompt/模型、工具 Harness 还是权限治理。

## What Changes

- 让所有生产模型调用统一经过 `ContextBuilder`，按预算组装当前意图、近期对话、滚动摘要、工具 schema、工具结果、制品引用和经确认的长期记忆。
- 建立事实优先级：最新实时工具证据高于仍适用的用户确认记忆，记忆高于历史摘要，历史摘要高于模型推断；冲突时不得用旧信息覆盖实时状态。
- 仅检索与当前节点、用户、任务和安全范围相关的已确认记忆；已删除、已修订、过期或越权记忆不得再次进入模型上下文。
- 将过大的工具结果保存为受控制品，只向模型提供有界预览、来源、截断状态和可审计引用。
- 建立最小 prompt 注册与版本约定，记录 `prompt_id`、版本、任务类型、模板、输入字段和变更说明。
- 记录脱敏的上下文组成与裁剪指标，并把评估失败区分为上下文、prompt/模型、工具 Harness 和治理四类。
- 在模型或上下文组装失败时保持确定性诊断工具、资源面板和安全操作控制路径可降级工作。
- 增加长对话、陈旧状态、错误记忆、prompt injection、大结果、命名空间越权和删除记忆残留等回归场景。
- 本次不实现自动 prompt 优化、自修改 Harness、多 Agent 辩论、向量数据库或通用 RAG、通用 Agent/Harness 平台、企业 SaaS/RBAC，也不允许跨节点经验自动获得执行权限。

## Capabilities

### New Capabilities

- `agent-context-runtime`: 统一生产上下文组装、预算、事实优先级、历史摘要、记忆检索、制品引用、命名空间隔离、降级与可观测性。
- `prompt-lifecycle`: prompt 注册、版本、输入契约、变更记录、运行关联和可重复评估要求。

### Modified Capabilities

无。

## Impact

- Agent Runtime 的所有模型调用入口将改为依赖统一上下文快照，而不是各自拼接消息。
- 现有 `ContextBuilder`、thread/checkpoint、memory、artifact、tool registry 和 provider 适配层需要统一数据契约与调用顺序。
- SQLite 与运行追踪将增加 prompt、上下文快照、裁剪原因和失败归因元数据；秘密与完整敏感正文仍不得写入普通日志。
- 离线评估与真实模型评估将增加上下文正确性、事实新鲜度、记忆隔离、prompt 版本覆盖和降级行为指标。
- 架构、威胁模型、评估指南和标准概念映射文档需要同步说明 Prompt 工程、Context 工程与 Harness 工程的职责边界。
