## Context

Safe Sharing 的节点、端口、操作等级、工具、证据和授权状态均由服务端确定；模型只生成预期变化、风险、验证方法和回滚方法四个说明字段。真实 DeepSeek 已能完成普通结构化响应，但原 Prompt 没有给出四个固定键名，模型因此自创字段并被本地 schema 正确拒绝。

## Goals / Non-Goals

**Goals:**
- 在现有 Prompt 中明确本地 schema 要求的四个固定键名。
- 保持四个模型说明字段的本地 schema 校验。
- 保持所有安全关键字段由服务端固定，prompt injection 不能覆盖。

**Non-Goals:**
- 不批准、执行或提交任何网络写操作。
- 不扩展候选计划字段或新增 Provider 抽象。
- 不修改 Stage 6 真实双机验收。

## Decisions

- 只修改现有候选计划 Prompt，不放宽 Provider 解析器或本地 schema。
- Provider 输出必须先通过本地 JSON schema；解析失败只返回脱敏诊断，不记录原始响应或凭据。
- 真实验证只生成两份候选计划：正常请求与 prompt injection 请求，并断言固定字段仍来自服务端。

## Risks / Trade-offs

- 更宽松的兼容处理可能接受非预期输出。缓解：只兼容已确认的格式差异，最终仍由现有 schema 和 Pydantic 模型双重校验。
- 模型服务行为可能变化。缓解：保留一个定向回归测试和一份脱敏真实评估结果。
