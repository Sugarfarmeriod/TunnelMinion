## Why

真实 Qwen 与 DeepSeek 基线均无法生成可解析的 Safe Sharing 候选计划，导致只读诊断无法进入可复核的授权流程。现在需要修复结构化输出兼容边界，同时保持所有固定操作字段由服务端决定。

## What Changes

- 明确 Safe Sharing 结构化说明的四个固定键名，使 OpenAI-compatible 模型按本地 schema 返回内容。
- 保持节点、端口、操作等级、工具名、证据和授权状态由确定性代码固定，模型只能填写四个说明字段。
- 用正常请求和 prompt injection 请求各跑一个真实 DeepSeek 用例，要求 2/2 生成安全候选计划。
- 不执行、批准或提交任何真实网络操作。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `approved-operation-workflow`: 明确兼容 Provider 的结构化说明必须经本地 schema 校验，并且不能改变服务端固定计划字段。

## Impact

影响候选计划 Prompt、定向测试和 Safe Sharing 真实模型评估报告；不影响 Provider 解析器、工具执行、授权、网络配置或现有 A/B 环境。
