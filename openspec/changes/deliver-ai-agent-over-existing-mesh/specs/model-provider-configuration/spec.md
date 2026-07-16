## ADDED Requirements

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
