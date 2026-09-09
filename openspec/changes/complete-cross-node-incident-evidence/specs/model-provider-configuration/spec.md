## ADDED Requirements

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
