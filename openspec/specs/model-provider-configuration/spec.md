# model-provider-configuration Specification

## Purpose

规定各节点独立配置 OpenAI-compatible 模型 Provider、保护 API Key、验证能力、更新配置和
安全删除配置的生命周期。

## Requirements
### Requirement: 用户可以在每个节点配置模型 Provider

Node Runtime SHALL 允许本机用户配置支持工具调用的模型 Provider，至少包含 endpoint、model identifier、API key 和请求超时。模型配置 MUST 属于当前节点，不得自动同步到其他节点。

#### Scenario: 保存有效模型配置

- **WHEN** 用户提交完整配置且最小连通与能力验证成功
- **THEN** Runtime 保存非秘密配置和受保护的 API key，并将模型状态标记为可用

#### Scenario: 拒绝不支持工具调用的模型

- **WHEN** 配置的模型无法完成要求的结构化工具调用验证
- **THEN** Runtime 不把该配置标记为 Agent 可用，并返回明确的能力不满足原因

### Requirement: 模型秘密只保存在本机

API key MUST 使用操作系统安全存储或仅当前系统账户可读的受限存储保存。API key MUST NOT 出现在远端工具请求、长期记忆、普通日志、评估报告或 Web API 响应中。

#### Scenario: 查看模型配置

- **WHEN** 本地面板读取当前模型配置
- **THEN** 响应只表明密钥是否已配置，不返回完整密钥

#### Scenario: 导出日志和评估报告

- **WHEN** 用户导出 Agent 日志或评估结果
- **THEN** 导出内容不包含 API key、认证头或可重放模型凭据

### Requirement: Runtime 验证模型可用性

Runtime MUST 提供显式模型验证操作，并区分认证失败、网络不可达、超时、模型不存在和能力不兼容。

#### Scenario: Provider 认证失败

- **WHEN** 模型验证收到认证失败响应
- **THEN** Runtime 将模型状态标记为不可用，并向本机用户返回认证失败而不是通用内部错误

### Requirement: 模型不可用时系统安全降级

模型 Provider 不可用时，Runtime SHALL 保持本地资源面板、确定性工具和远端网关运行，但 MUST 拒绝启动新的 AI 对话 run 并解释原因。

#### Scenario: 模型在运行期间超时

- **WHEN** 活动对话的模型调用超过配置超时
- **THEN** Runtime 终止或降级该 run、保留已有工具证据，并且不影响资源面板和节点工具服务

### Requirement: 节点可以删除模型配置

本机用户 MUST 能删除模型配置及保存的密钥。删除后新 run MUST 无法使用旧凭据，历史会话中也不得恢复密钥。

#### Scenario: 用户删除模型配置

- **WHEN** 用户确认删除当前模型 Provider
- **THEN** Runtime 移除受保护密钥、将模型状态标记为未配置，并拒绝后续模型调用

### Requirement: 模型切换必须保留非秘密配置并隔离 endpoint 凭据

Node Runtime MUST 在始终只激活一个模型 Provider 的前提下，保留已成功验证的非秘密配置供本机用户切回。API key MUST 只按规范化 endpoint 从本机秘密存储读取；切换到另一 endpoint 时不得复用、覆盖或发送前一 endpoint 的凭据。Web API 和页面只能显示配置字段及密钥是否存在，不得返回、缓存或导出完整密钥。

#### Scenario: 从 DeepSeek 切到 Qwen 后再切回

- **WHEN** 用户已保存 DeepSeek endpoint、model 和 API key，随后保存无密钥的本机 Qwen 配置，再从已保存配置中选择 DeepSeek
- **THEN** 系统保留两份非秘密配置，Qwen 验证不接收 DeepSeek 密钥，切回 DeepSeek 时只复用 DeepSeek endpoint 对应的本机密钥并重新验证后激活

#### Scenario: 切换到未保存密钥的新 endpoint

- **WHEN** 用户选择或填写另一 endpoint 且没有为该 endpoint 提交 API key
- **THEN** Runtime 只以无密钥请求验证该 endpoint，不得读取或发送其他 endpoint 的密钥

#### Scenario: 读取旧版单配置

- **WHEN** 节点升级时存在旧版单配置 JSON 和无法证明 endpoint 归属的通用密钥槽
- **THEN** Runtime 把非秘密配置作为一个可见档案读取，但不自动绑定或发送通用密钥，并要求用户为目标 endpoint 重新提交一次密钥

#### Scenario: 清除全部模型配置

- **WHEN** 用户明确确认清除模型配置与密钥
- **THEN** Runtime 删除全部已保存非秘密配置、每个可推导 endpoint 的本机密钥及旧版通用密钥槽，后续 AI run 保持不可用

#### Scenario: OpenAI-compatible 云端模型进行多轮工具调查

- **WHEN** 已验证模型使用 Chat Completions 的 JSON object 模式，并在思考模式工具响应中返回 `reasoning_content`
- **THEN** Provider 把终态 JSON Schema 和必须调用工具的要求作为系统约束发送并由 Runtime 校验实际返回，不发送思考模式不兼容的 `tool_choice` 或工具结果冗余字段，只在当前内存工具循环中原样回传 `reasoning_content`，不得把该推理字段写入公开快照或报告
