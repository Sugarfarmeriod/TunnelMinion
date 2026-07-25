# Prompt Lifecycle

## Purpose

规定生产 Prompt 的稳定注册、语义版本、声明式输入契约、可复现评估和脱敏失败归因，并明确
模型不得自动修改 Prompt、Harness、工具注册或权限策略的安全边界。

## Requirements

### Requirement: 每个生产 prompt 必须注册稳定身份与版本
系统 MUST 为每个生产 prompt 定义 `prompt_id`、语义版本、任务类型、模板、允许输入字段和中文变更说明，并 SHALL 在运行记录中关联实际使用的版本与内容哈希。

#### Scenario: prompt 模板发生行为变化
- **WHEN** 开发者修改 prompt 的约束、输出契约或工具使用策略
- **THEN** 系统 SHALL 要求更新 prompt 版本和变更说明，否则质量门禁失败

### Requirement: prompt 输入必须遵守声明契约
系统 SHALL 仅把 prompt 注册项声明的结构化输入字段传入模板，并 MUST 将工具结果、远端文本、历史和记忆视为数据而非可修改系统规则的指令。

#### Scenario: 远端文本伪装成系统指令
- **WHEN** 工具结果或记忆包含与系统规则冲突的指令文本
- **THEN** prompt 渲染 SHALL 保持其不可信数据边界，不得把该文本提升到系统约束或开发者指令位置

### Requirement: prompt 运行必须可复现且不泄露秘密
系统 SHALL 记录 prompt 版本、内容哈希、模型/provider、上下文快照和脱敏输入摘要，以支持离线复现；运行记录 MUST NOT 包含模型密钥、完整凭据或认证头。

#### Scenario: 比较两个 prompt 版本
- **WHEN** 评估人员比较同一固定上下文快照在两个 prompt 版本上的结果
- **THEN** 系统 SHALL 能关联各自的版本、模型参数、输出、延迟、token、成本和评估结果

### Requirement: prompt 变更必须经过黄金与对抗评估
系统 SHALL 为生产 prompt 维护与任务类型对应的黄金场景和安全对抗场景，并 MUST 在版本发布前比较任务正确性、证据引用、安全拦截、延迟和成本。

#### Scenario: 新版本提高完成率但降低安全拦截
- **WHEN** 候选 prompt 版本提高任务完成率但使任一零容忍安全场景失败
- **THEN** 系统 SHALL 阻止该版本成为生产默认版本

### Requirement: 失败必须按工程边界分类
系统 SHALL 将评估与生产失败至少分为 `context`、`prompt_or_model`、`harness_or_tool` 和 `governance`，并 SHALL 保存支持分类的脱敏证据。

#### Scenario: 模型使用了错误端口
- **WHEN** 运行结果包含错误端口
- **THEN** 评估 SHALL 根据上下文快照是否包含正确实时证据、prompt 是否正确约束、工具是否正确返回以及策略是否正确拦截来确定失败类别

### Requirement: prompt 系统不得自动修改自身或扩大权限
系统 MUST NOT 允许模型根据单次运行结果自动修改生产 prompt、Harness、工具注册或授权策略，也 MUST NOT 把 prompt 长度、Agent 数量、RAG 存在与否或 Harness 层数作为完成度指标。

#### Scenario: 模型建议永久采用自身生成的 prompt
- **WHEN** 模型输出要求把本次生成的指令保存为生产 prompt 或授予更多工具权限
- **THEN** 系统 SHALL 仅把内容视为普通建议，不得自动更新注册表、部署配置或权限策略
